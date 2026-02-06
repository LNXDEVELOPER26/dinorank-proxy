import os
import re
import json
import time
import base64
import random
import logging
from collections import defaultdict
from threading import Lock, Thread, Event
from flask import Flask, request, Response, stream_with_context, make_response, redirect
from curl_cffi import requests as crequests
from dotenv import load_dotenv
from waitress import serve

try:
    from cookie_monitor import cookie_monitor, auto_renew_if_needed
    COOKIE_MONITOR_AVAILABLE = True
    logging.info("Cookie monitor loaded - auto-renewal enabled")
except ImportError:
    COOKIE_MONITOR_AVAILABLE = False
    logging.warning("Cookie monitor unavailable - auto-renewal disabled")

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

PORT = int(os.getenv("PORT_DINORANK", 4040))
TARGET_URL = "https://dinorank.com"
MY_DOMAIN = "dinorank.seoconjunta.net"
PROXY_URL = f"https://{MY_DOMAIN}"
PROXY_DOMAIN = MY_DOMAIN
UPSTREAM_PROXY = os.getenv("UPSTREAM_PROXY")
TOKEN_EXPIRY = 18000

# CRITICAL: Must match session User-Agent
MOBILE_USER_AGENT = "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36"

SECRET_KEY = os.getenv("SECRET_KEY", "")

rate_limit_store = defaultdict(list)
rate_limit_lock = Lock()
MAX_REQUESTS_PER_MINUTE = 600
MAX_REQUESTS_PER_MINUTE_STATIC = 2000

STATIC_EXTENSIONS = {
    '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.otf', '.webp', '.mp4', '.webm'
}

cache_store = {}
cache_lock = Lock()
CACHE_TTL = 300
CACHE_MAX_SIZE = 1000

MAX_RETRIES = 3
INITIAL_BACKOFF = 1
MAX_BACKOFF = 10

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", f"https://{MY_DOMAIN}").split(",")

cookies_lock = Lock()

def load_cookies_from_env():
    """Load cookies from .env file."""
    load_dotenv(override=True)

    raw_cookie = os.getenv("OPENID") or os.getenv("MASTER_COOKIES") or ""
    raw_cookie = raw_cookie.strip()

    for p in ["OPENID=", "MASTER_COOKIES=", "Cookies="]:
        if raw_cookie.startswith(p):
            raw_cookie = raw_cookie.replace(p, "", 1)

    cookies = {}
    if raw_cookie:
        for c in raw_cookie.split(';'):
            if '=' in c:
                try:
                    k, v = c.strip().split('=', 1)
                    cookies[k.strip()] = v.strip()
                except Exception as e:
                    logger.warning(f"Error parsing cookie: {e}")

    logger.info(f"Cookies loaded: {len(cookies)}")
    critical_cookies = ['PHPSESSID', 'userId', 'comp', 'compx', 'pass']
    for cookie in critical_cookies:
        if cookie in cookies:
            logger.info(f"  ✓ {cookie}: {cookies[cookie][:20]}...")
        else:
            logger.warning(f"  ✗ {cookie}: NOT FOUND")

    return cookies

def reload_cookies():
    """Reload cookies from .env after renewal."""
    global COOKIES
    with cookies_lock:
        logger.info("Reloading cookies from .env...")
        COOKIES = load_cookies_from_env()
        logger.info(f"Cookies reloaded: {len(COOKIES)}")
        return COOKIES

COOKIES = load_cookies_from_env()

def php_decode(encoded_data):
    """Decode token using PHP-compatible algorithm (inverse of envato1.php encode)."""
    try:
        decoded_chars = ''.join(chr(ord(c) - 1) for c in encoded_data)
        result = base64.b64decode(decoded_chars).decode('utf-8')
        return result
    except Exception as e:
        logger.error(f"PHP decode error: {type(e).__name__}")
        return None

def php_encode(data):
    """Encode token using PHP-compatible algorithm (same as envato1.php)."""
    try:
        encoded = base64.b64encode(data.encode('utf-8')).decode('utf-8')
        result = ''.join(chr(ord(c) + 1) for c in encoded)
        return result
    except Exception as e:
        logger.error(f"PHP encode error: {type(e).__name__}")
        return None

def create_token(user_id, email):
    """Create token compatible with PHP system (envato1.php format)."""
    timestamp = int(time.time())
    message = f"{user_id}|{email}|{timestamp}"
    return php_encode(message)

def decode_token(token):
    """Decode and validate token from PHP system (ID|email|timestamp)."""
    try:
        decoded = php_decode(token)
        if not decoded:
            return None

        parts = decoded.split("|")

        if len(parts) != 3:
            logger.warning(f"Invalid token format: expected 3 parts, got {len(parts)}")
            return None

        user_id, email, timestamp_str = parts
        timestamp = int(timestamp_str)

        if time.time() - timestamp > TOKEN_EXPIRY:
            logger.warning(f"Token expired for user: {email}")
            return None

        return {"user_id": user_id, "email": email, "timestamp": timestamp}

    except Exception as e:
        logger.error(f"Token decode error: {type(e).__name__}")
        return None

def is_static_resource(path):
    """Check if path is a static resource."""
    path_lower = path.lower()
    return any(path_lower.endswith(ext) for ext in STATIC_EXTENSIONS)

def get_from_cache(cache_key):
    """Get content from cache if not expired."""
    with cache_lock:
        if cache_key in cache_store:
            cached_data, timestamp = cache_store[cache_key]
            if time.time() - timestamp < CACHE_TTL:
                logger.info(f"Cache HIT: {cache_key}")
                return cached_data
            else:
                del cache_store[cache_key]
                logger.info(f"Cache EXPIRED: {cache_key}")
        return None

def save_to_cache(cache_key, data):
    """Save content to cache with LRU eviction."""
    with cache_lock:
        if len(cache_store) >= CACHE_MAX_SIZE:
            oldest_key = min(cache_store.keys(), key=lambda k: cache_store[k][1])
            del cache_store[oldest_key]
            logger.info(f"Cache EVICTED: {oldest_key}")

        cache_store[cache_key] = (data, time.time())
        logger.info(f"Cache SAVED: {cache_key}")

def make_request_with_retry(method, url, headers, cookies, data, proxies, impersonate, timeout):
    """Make HTTP request with exponential backoff retry for 429 errors."""
    for attempt in range(MAX_RETRIES):
        try:
            resp = crequests.request(
                method=method,
                url=url,
                headers=headers,
                cookies=cookies,
                data=data,
                allow_redirects=False,
                impersonate=impersonate,
                proxies=proxies,
                timeout=timeout
            )

            if resp.status_code == 429:
                if attempt < MAX_RETRIES - 1:
                    backoff = min(INITIAL_BACKOFF * (2 ** attempt), MAX_BACKOFF)
                    logger.warning(f"Received 429 from DinoRank. Retrying in {backoff}s (attempt {attempt + 1}/{MAX_RETRIES})")
                    time.sleep(backoff)
                    continue
                else:
                    logger.error(f"Max retries reached for 429 error from DinoRank")
                    return resp

            return resp

        except crequests.exceptions.Timeout as e:
            if attempt < MAX_RETRIES - 1:
                backoff = min(INITIAL_BACKOFF * (2 ** attempt), MAX_BACKOFF)
                logger.warning(f"Request timeout. Retrying in {backoff}s (attempt {attempt + 1}/{MAX_RETRIES})")
                time.sleep(backoff)
                continue
            else:
                raise

    return resp

def check_rate_limit(client_ip, is_static=False):
    """Smart rate limiting with different limits for static resources."""
    with rate_limit_lock:
        now = time.time()
        minute_ago = now - 60

        rate_limit_store[client_ip] = [
            req_time for req_time in rate_limit_store[client_ip]
            if req_time > minute_ago
        ]

        limit = MAX_REQUESTS_PER_MINUTE_STATIC if is_static else MAX_REQUESTS_PER_MINUTE

        if len(rate_limit_store[client_ip]) >= limit:
            return False

        rate_limit_store[client_ip].append(now)
        return True

class SessionKeepalive:
    """
    Background thread that pings DinoRank periodically to keep session alive.
    Integrates with cookie_monitor for auto-renewal on expiration.
    """

    def __init__(self, interval_hours, endpoint, user_agent, get_cookies_func, target_url):
        self.interval_seconds = interval_hours * 3600
        self.endpoint = endpoint
        self.user_agent = user_agent
        self.get_cookies = get_cookies_func
        self.target_url = target_url
        self.thread = None
        self.stop_event = Event()
        self.backoff_multiplier = 1
        self.max_backoff = 8

    def _keepalive_loop(self):
        """Main keepalive loop running in background thread."""
        logger.info("=" * 80)
        logger.info("Keepalive thread started")
        logger.info(f"  Interval: {self.interval_seconds / 3600:.1f} hours")
        logger.info(f"  Endpoint: {self.endpoint}")
        logger.info("=" * 80)

        while not self.stop_event.is_set():
            jitter = random.randint(-300, 300)
            sleep_time = (self.interval_seconds * self.backoff_multiplier) + jitter

            next_ping_hours = sleep_time / 3600
            logger.info(f"Next keepalive ping in {next_ping_hours:.2f} hours")

            elapsed = 0
            while elapsed < sleep_time and not self.stop_event.is_set():
                self.stop_event.wait(60)
                elapsed += 60

            if self.stop_event.is_set():
                break

            if COOKIE_MONITOR_AVAILABLE and cookie_monitor.is_renewing:
                logger.info("Cookie renewal in progress, skipping this keepalive ping")
                continue

            try:
                status_code, response_time = self._make_keepalive_request()
                self._handle_response(status_code)

                if status_code == 200:
                    self.backoff_multiplier = 1
                    logger.info(f"✓ Keepalive ping successful (200, {response_time:.0f}ms)")

            except Exception as e:
                logger.error(f"Keepalive ping error: {type(e).__name__} - {str(e)}")

        logger.info("Keepalive thread stopped")

    def _make_keepalive_request(self):
        """Make GET request to keepalive endpoint."""
        with cookies_lock:
            current_cookies = COOKIES.copy()

        headers = {
            "Host": "dinorank.com",
            "Origin": self.target_url,
            "Referer": self.target_url + "/",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": self.user_agent,
            "Accept-Encoding": "identity"
        }

        url = f"{self.target_url}{self.endpoint}"
        start_time = time.time()

        try:
            resp = crequests.get(
                url=url,
                headers=headers,
                cookies=current_cookies,
                impersonate="chrome_android",
                timeout=30,
                allow_redirects=False
            )

            response_time = (time.time() - start_time) * 1000
            return resp.status_code, response_time

        except crequests.exceptions.Timeout:
            logger.warning("Keepalive ping timeout, retrying once...")

            try:
                resp = crequests.get(
                    url=url,
                    headers=headers,
                    cookies=current_cookies,
                    impersonate="chrome_android",
                    timeout=60,
                    allow_redirects=False
                )
                response_time = (time.time() - start_time) * 1000
                return resp.status_code, response_time

            except Exception:
                logger.error("Keepalive ping failed after retry")
                return 0, 0

    def _handle_response(self, status_code):
        """Handle different HTTP response codes."""
        if status_code == 200:
            return False

        if status_code in [401, 403]:
            logger.warning(f"⚠ Keepalive detected expired/invalid cookies ({status_code})")

            if COOKIE_MONITOR_AVAILABLE:
                logger.info("→ Triggering cookie auto-renewal...")
                success = auto_renew_if_needed(
                    status_code,
                    f"{self.target_url}{self.endpoint}",
                    "Keepalive detected expired session"
                )

                if success:
                    with cookies_lock:
                        reload_cookies()
                    logger.info("✓ Cookies renewed, keepalive resumed")
                    return True
                else:
                    logger.error("✗ Auto-renewal failed, continuing with current cookies")
            else:
                logger.error("Cookie monitor unavailable, cannot auto-renew")

            return False

        if status_code == 429:
            self.backoff_multiplier = min(self.backoff_multiplier * 2, self.max_backoff)
            logger.warning(f"⚠ Rate limit detected (429), backoff {self.backoff_multiplier}x")
            return False

        if status_code in [301, 302, 303, 307, 308]:
            logger.warning(f"⚠ Keepalive received redirect ({status_code}), possible expired session")
            if COOKIE_MONITOR_AVAILABLE:
                auto_renew_if_needed(status_code, "", "Keepalive detected redirect")
            return False

        if 500 <= status_code < 600:
            logger.warning(f"⚠ DinoRank server error ({status_code}), not a cookie issue")
            return False

        if status_code == 0:
            logger.warning("⚠ Keepalive ping timeout, skipping this cycle")
            return False

        logger.warning(f"⚠ Keepalive received unexpected code: {status_code}")
        return False

    def start(self):
        """Start keepalive thread in background."""
        if self.thread and self.thread.is_alive():
            logger.warning("Keepalive thread already running")
            return

        self.stop_event.clear()
        self.thread = Thread(target=self._keepalive_loop, daemon=True)
        self.thread.start()

    def stop(self):
        """Stop keepalive thread gracefully."""
        if self.thread and self.thread.is_alive():
            logger.info("Stopping keepalive thread...")
            self.stop_event.set()
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                logger.warning("Keepalive thread did not terminate in time, but marked for stop")

keepalive = None

ACCESS_DENIED_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Acceso Denegado</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .container { text-align: center; padding: 40px; background: rgba(255,255,255,0.05); border-radius: 20px; backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1); max-width: 500px; }
        h1 { color: #ff6b6b; font-size: 2.5rem; margin-bottom: 20px; }
        p { color: #a0a0a0; font-size: 1.1rem; line-height: 1.6; margin-bottom: 30px; }
        a { display: inline-block; padding: 15px 40px; background: linear-gradient(135deg, #10a37f 0%, #1a7f64 100%); color: white; text-decoration: none; border-radius: 30px; font-weight: 600; transition: transform 0.3s, box-shadow 0.3s; }
        a:hover { transform: translateY(-3px); box-shadow: 0 10px 30px rgba(16, 163, 127, 0.4); }
    </style>
</head>
<body>
    <div class="container">
        <h1>Acceso Denegado</h1>
        <p>Debes acceder a través del panel de seoconjuntas.net para ver este contenido.</p>
        <a href="https://seoconjuntas.net/herramientas-premium/">Ir al Panel</a>
    </div>
</body>
</html>
"""

@app.route("/r/<token>")
def validate_token(token):
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    if not check_rate_limit(client_ip, is_static=False):
        logger.warning(f"Rate limit exceeded for IP: {client_ip} (token validation)")
        return Response("Too many requests", status=429)

    user_data = decode_token(token)
    if user_data:
        logger.info(f"Valid token for user: {user_data['email']}")
        resp = make_response(redirect("/"))
        resp.set_cookie(
            "__Host-dinorank_session",
            token,
            max_age=TOKEN_EXPIRY,
            httponly=True,
            secure=True,
            samesite="Strict",
            path="/"
        )
        return resp

    logger.warning(f"Invalid token attempt from IP: {client_ip}")
    return Response(ACCESS_DENIED_HTML, status=403, mimetype="text/html")

@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def proxy(path):
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    if path == "" and request.method == "GET":
        logger.info(f"Redirecting / to /homed/ for IP: {client_ip}")
        return redirect("/homed/", code=302)

    is_static = is_static_resource(path)
    if not check_rate_limit(client_ip, is_static=is_static):
        resource_type = "static resource" if is_static else "dynamic request"
        logger.warning(f"Rate limit exceeded for IP: {client_ip} ({resource_type}: /{path})")
        return Response("Too many requests", status=429)

    if request.method == "OPTIONS":
        origin = request.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            return Response("", status=200, headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept, Accept-Language, X-Requested-With"
            })
        return Response("", status=403)

    session_token = request.cookies.get("__Host-dinorank_session") or request.cookies.get("dinorank_session")
    user_data = decode_token(session_token) if session_token else None

    if not user_data:
        logger.info(f"Unauthorized access attempt to /{path} from IP: {client_ip}")
        if 'application/json' in request.headers.get('Accept', ''):
            return Response(json.dumps({"error": "Unauthorized"}), status=403, mimetype="application/json")
        return Response(ACCESS_DENIED_HTML, status=403, mimetype="text/html")

    qs = request.query_string.decode("utf-8")
    url = f"{TARGET_URL}/{path}" + (f"?{qs}" if qs else "")

    logger.info(f"Request: {request.method} /{path} -> {url}")

    cache_key = None
    if request.method == "GET" and is_static:
        cache_key = f"{path}?{qs}" if qs else path
        cached_response = get_from_cache(cache_key)
        if cached_response:
            return Response(
                cached_response['content'],
                status=cached_response['status'],
                headers=cached_response['headers']
            )

    headers = {
        "Host": "dinorank.com",
        "Origin": TARGET_URL,
        "Referer": TARGET_URL + "/",
        "Accept-Encoding": "identity",
        "User-Agent": MOBILE_USER_AGENT,
    }

    allowed = ["authorization", "content-type", "accept", "accept-language", "x-requested-with"]
    for k, v in request.headers.items():
        if k.lower() in allowed:
            headers[k] = v

    proxies = {"https": UPSTREAM_PROXY, "http": UPSTREAM_PROXY} if UPSTREAM_PROXY else None

    if not any(path.endswith(ext) for ext in ['.css', '.js', '.png', '.jpg', '.svg', '.woff', '.woff2', '.ttf']):
        logger.info(f"Sending {len(COOKIES)} cookies to DinoRank")
        logger.info(f"User-Agent: {headers['User-Agent'][:50]}...")

    try:
        resp = make_request_with_retry(
            method=request.method,
            url=url,
            headers=headers,
            cookies=COOKIES,
            data=request.get_data(),
            proxies=proxies,
            impersonate="chrome_android",
            timeout=180
        )

        content = resp.content
        c_type = resp.headers.get("Content-Type", "").lower()

        if resp.status_code in [301, 302, 303, 307, 308]:
            location = resp.headers.get("Location", "")
            logger.warning(f"Redirect detected: {resp.status_code} -> {location}")
            if "login" in location.lower() or "acceso" in location.lower():
                logger.error("DinoRank redirecting to LOGIN! Cookies may have expired.")

                if COOKIE_MONITOR_AVAILABLE:
                    logger.info("Starting cookie auto-renewal...")
                    if auto_renew_if_needed(resp.status_code, url, "Login redirect detected"):
                        reload_cookies()
                        logger.info("Cookies renewed. Retrying request...")

                        resp = make_request_with_retry(
                            method=request.method,
                            url=url,
                            headers=headers,
                            cookies=COOKIES,
                            data=request.get_data(),
                            proxies=proxies,
                            impersonate="chrome_android",
                            timeout=180
                        )
                        content = resp.content
                        c_type = resp.headers.get("Content-Type", "").lower()
                        logger.info("Request retried successfully with new cookies")
                    else:
                        logger.error("Auto-renewal failed")
                else:
                    logger.error("Cookie monitor unavailable. Manual renewal required")

        elif resp.status_code == 401:
            logger.error("401 Unauthorized response! Cookies are invalid.")

            if COOKIE_MONITOR_AVAILABLE:
                logger.info("Starting cookie auto-renewal...")
                if auto_renew_if_needed(resp.status_code, url, "401 Unauthorized"):
                    reload_cookies()
                    logger.info("Cookies renewed. Retrying request...")

                    resp = make_request_with_retry(
                        method=request.method,
                        url=url,
                        headers=headers,
                        cookies=COOKIES,
                        data=request.get_data(),
                        proxies=proxies,
                        impersonate="chrome_android",
                        timeout=180
                    )
                    content = resp.content
                    c_type = resp.headers.get("Content-Type", "").lower()
                    logger.info("Request retried successfully with new cookies")
                else:
                    logger.error("Auto-renewal failed")

        text_types = ["text", "json", "javascript", "application/javascript",
                      "application/x-javascript", "css", "html", "xml"]

        is_ajax_response = "/seo/ajax/" in path or path.startswith("seo/ajax/")

        if any(x in c_type for x in text_types) and not is_ajax_response:
            try:
                body_str = content.decode("utf-8", errors="ignore")

                # Rewrite DinoRank URLs to relative paths (works in localhost and production)
                body_str = body_str.replace("https://dinorank.com/", "/")
                body_str = body_str.replace("http://dinorank.com/", "/")
                body_str = body_str.replace("https://dinorank.com", "")
                body_str = body_str.replace("http://dinorank.com", "")

                body_str = body_str.replace("//dinorank.com/", "/")
                body_str = body_str.replace("//dinorank.com", "")

                body_str = body_str.replace("https:\\/\\/dinorank.com\\/", "\\/")
                body_str = body_str.replace("http:\\/\\/dinorank.com\\/", "\\/")
                body_str = body_str.replace("\\/\\/dinorank.com\\/", "\\/")

                body_str = body_str.replace("dinorank.com", PROXY_DOMAIN)

                # DinoRank has hardcoded localhost URLs in AJAX calls
                body_str = body_str.replace("http://localhost/seo/", "/seo/")
                body_str = body_str.replace("http:\\/\\/localhost\\/seo\\/", "\\/seo\\/")
                body_str = body_str.replace("'localhost/seo/", "'/seo/")
                body_str = body_str.replace('"localhost/seo/', '"/seo/')

                # Fix WordPress/Jetpack CDN image optimization
                body_str = body_str.replace("i0.wp.com/dinorank.seoconjunta.net", PROXY_DOMAIN)
                body_str = body_str.replace("i1.wp.com/dinorank.seoconjunta.net", PROXY_DOMAIN)
                body_str = body_str.replace("i2.wp.com/dinorank.seoconjunta.net", PROXY_DOMAIN)

                if "html" in c_type:
                    body_str = re.sub(r'\s+integrity="[^"]*"', '', body_str)
                    body_str = re.sub(r"\s+integrity='[^']*'", '', body_str)
                    body_str = re.sub(r'\s+crossorigin="[^"]*"', '', body_str)
                    body_str = re.sub(r"\s+crossorigin='[^']*'", '', body_str)

                    custom_css = """
<style>
/* Hide user menu */
.user-menu-wrapper,
#user-menu-wrapper {
    display: none !important;
}

/* Hide DinoRank promotional banners */
#botoncomprartextossueltosoenpack,
.busquedatextocontenidogenerado,
.comprartextostextosuperior {
    display: none !important;
}

/* Hide pink banner by background color */
div[style*="rgb(243, 88, 138)"],
div[style*="rgb(243, 89, 138)"],
div[style*="#f35889"],
div[style*="#f3588a"],
div[style*="linear-gradient"][style*="243, 88"] {
    display: none !important;
}

/* Hide common banner classes */
.upgrade-banner,
.promo-banner,
.subscription-banner,
.upsell-banner,
.content-banner,
div[class*="upgrade"],
div[class*="promo"],
div[class*="upsell"],
div[class*="purchase"],
div[class*="buy-more"],
div[class*="comprar"] {
    display: none !important;
}

/* Hide promotional alerts */
.alert-upgrade,
.notice-upgrade,
.notification-upgrade {
    display: none !important;
}
</style>
"""
                    if '</head>' in body_str:
                        body_str = body_str.replace('</head>', custom_css + '</head>', 1)

                    css_urls = re.findall(r'href=["\']([^"\']*\.css[^"\']*)["\']', body_str)
                    js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', body_str)

                    external_domains = set()
                    for url in css_urls + js_urls:
                        if url.startswith('http') and 'dinorank' not in url.lower():
                            domain = url.split('/')[2] if len(url.split('/')) > 2 else url
                            external_domains.add(domain)

                    if external_domains:
                        logger.warning(f"External resources detected: {external_domains}")

                    logger.info(f"CSS found: {len(css_urls)}, JS found: {len(js_urls)}")
                    if css_urls:
                        logger.info(f"First 3 CSS: {css_urls[:3]}")
                    if js_urls:
                        logger.info(f"First 3 JS: {js_urls[:3]}")

                    jquery_cdn = '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>'

                    if '<head>' in body_str:
                        body_str = body_str.replace('<head>', f'<head>\n{jquery_cdn}', 1)
                    elif '<head ' in body_str:
                        body_str = re.sub(r'(<head[^>]*>)', rf'\1\n{jquery_cdn}', body_str, count=1)

                content = body_str.encode("utf-8")

            except Exception as e:
                logger.error(f"Error rewriting content: {type(e).__name__}")

        exclude = [
            "content-encoding", "content-length", "transfer-encoding", "connection",
            "content-security-policy", "set-cookie", "upgrade", "keep-alive",
            "proxy-authenticate", "proxy-authorization", "te", "trailers"
        ]
        r_headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in exclude]

        origin = request.headers.get("Origin")
        if origin and origin in ALLOWED_ORIGINS:
            r_headers.append(("Access-Control-Allow-Origin", origin))
            r_headers.append(("Access-Control-Allow-Credentials", "true"))
        else:
            r_headers.append(("Access-Control-Allow-Origin", "*"))

        if c_type:
            r_headers = [(k, v) for k, v in r_headers if k.lower() != "content-type"]
            r_headers.append(("Content-Type", c_type))

        logger.info(f"Proxied: {request.method} /{path} -> {resp.status_code} ({c_type}) - {len(content)} bytes")

        if cache_key and resp.status_code == 200 and is_static:
            save_to_cache(cache_key, {
                'content': content,
                'status': resp.status_code,
                'headers': r_headers
            })

        return Response(content, status=resp.status_code, headers=r_headers)

    except crequests.exceptions.Timeout as e:
        logger.error(f"Timeout for {url}: {type(e).__name__}")
        return Response("Request timeout", status=504)
    except Exception as e:
        logger.error(f"Proxy error for {url}: {type(e).__name__} - {str(e)}")
        return Response("Service temporarily unavailable", status=502)

if __name__ == "__main__":
    logger.info("=" * 80)
    logger.info(f"Starting DinoRank Proxy on port {PORT}")
    logger.info(f"Allowed origins: {ALLOWED_ORIGINS}")
    logger.info(f"Rate limits - Dynamic: {MAX_REQUESTS_PER_MINUTE} req/min, Static: {MAX_REQUESTS_PER_MINUTE_STATIC} req/min")
    logger.info(f"Cache - TTL: {CACHE_TTL}s, Max size: {CACHE_MAX_SIZE} items")
    logger.info(f"Retries - Max: {MAX_RETRIES}, Backoff: {INITIAL_BACKOFF}s to {MAX_BACKOFF}s")

    keepalive_enabled = os.getenv("KEEPALIVE_ENABLED", "true").lower() == "true"

    if keepalive_enabled:
        try:
            keepalive_interval = float(os.getenv("KEEPALIVE_INTERVAL_HOURS", "4.5"))
            keepalive_endpoint = os.getenv("KEEPALIVE_ENDPOINT", "/homed/")

            logger.info(f"Session keepalive - Enabled: Yes, Interval: {keepalive_interval}h, Endpoint: {keepalive_endpoint}")

            keepalive = SessionKeepalive(
                interval_hours=keepalive_interval,
                endpoint=keepalive_endpoint,
                user_agent=MOBILE_USER_AGENT,
                get_cookies_func=lambda: COOKIES,
                target_url=TARGET_URL
            )
            keepalive.start()

        except Exception as e:
            logger.error(f"Error starting keepalive: {e}")
            logger.warning("Continuing without keepalive...")
    else:
        logger.info("Session keepalive - Disabled")

    logger.info("=" * 80)
    serve(
        app,
        host="0.0.0.0",
        port=PORT,
        threads=200,
        connection_limit=500,
        channel_timeout=180,
        cleanup_interval=10,
        backlog=2048
    )
