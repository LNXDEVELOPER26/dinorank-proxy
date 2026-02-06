#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auto-login to DinoRank and extract session cookies from this server's IP.
Uses curl-cffi to emulate a real browser.
"""
import os
import sys
import re
from datetime import datetime
from curl_cffi import requests as crequests
from dotenv import load_dotenv
import shutil

load_dotenv()

print("DinoRank Auto-Login & Cookie Extractor")
print("Logging in and extracting cookies from this server's IP...\n")

email = os.getenv("DINORANK_EMAIL", "").strip()
password = os.getenv("DINORANK_PASSWORD", "").strip()

if not email or not password:
    print("[ERROR] Credentials not configured in .env")
    print("Configure: DINORANK_EMAIL=your_email@example.com")
    print("           DINORANK_PASSWORD=your_password\n")
    sys.exit(1)

email_display = email[:3] + "*" * (len(email) - 6) + email[-3:] if len(email) > 6 else "***"
password_display = "*" * len(password)
print(f"[OK] Loaded credentials - Email: {email_display}, Password: {password_display}\n")
print("Starting login session...\n")

USER_AGENT = "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36"
session = crequests.Session()

try:
    print("[1/4] Accessing login page...")
    resp = session.get(
        "https://dinorank.com/login/",
        impersonate="chrome_android",
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
        },
        timeout=60
    )

    if resp.status_code != 200:
        print(f"[ERROR] Failed to access login page: {resp.status_code}\n")
        sys.exit(1)

    print(f"[OK] Login page retrieved ({len(session.cookies)} initial cookies)")

    print("[2/4] Parsing login form...")
    html = resp.text

    # Extract CSRF token - try multiple common patterns
    csrf_token = None
    csrf_patterns = [
        r'<input[^>]*name=["\']csrf[^"\']*["\'][^>]*value=["\']([^"\']+)["\']',
        r'<input[^>]*value=["\']([^"\']+)["\'][^>]*name=["\']csrf[^"\']*["\']',
        r'<input[^>]*name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
        r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
    ]
    for pattern in csrf_patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            csrf_token = match.group(1)
            break

    # Extract email field name - handles variations in different forms
    email_field = "email"
    email_patterns = [
        r'<input[^>]*name=["\']([^"\']*(?:email|usuario|user|login)[^"\']*)["\'][^>]*type=["\'](?:text|email)',
        r'<input[^>]*type=["\'](?:text|email)["\'][^>]*name=["\']([^"\']*(?:email|usuario|user|login)[^"\']*)["\']',
    ]
    for pattern in email_patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            email_field = match.group(1)
            break

    # Extract password field name
    password_field = "password"
    password_patterns = [
        r'<input[^>]*name=["\']([^"\']*(?:password|pass|clave|contrase)[^"\']*)["\'][^>]*type=["\']password',
        r'<input[^>]*type=["\']password["\'][^>]*name=["\']([^"\']*)["\']',
    ]
    for pattern in password_patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            password_field = match.group(1)
            break

    print(f"[OK] Form fields: {email_field}, {password_field}" + (" (CSRF token found)" if csrf_token else ""))

    print("[3/4] Sending credentials...")

    login_data = {
        email_field: email,
        password_field: password,
    }

    if csrf_token:
        for token_name in ['csrf_token', '_token', 'csrf', 'token']:
            if token_name not in login_data:
                login_data[token_name] = csrf_token
                break

    resp = session.post(
        "https://dinorank.com/login/",
        data=login_data,
        impersonate="chrome_android",
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://dinorank.com",
            "Referer": "https://dinorank.com/login/",
        },
        allow_redirects=True,
        timeout=30
    )

    # Check for successful login indicators
    success_indicators = [
        "logout" in resp.text.lower(),
        "cerrar sesión" in resp.text.lower() or "cerrar sesion" in resp.text.lower(),
        "salir" in resp.text.lower() and "usuario" in resp.text.lower(),
        "/homed/" in resp.url.lower(),
        "/dashboard" in resp.url.lower(),
        "userId" in str(session.cookies),
        "PHPSESSID" in str(session.cookies),
    ]

    if any(success_indicators):
        print(f"[OK] Login successful - URL: {resp.url}")
    else:
        print(f"[WARNING] Response: {resp.status_code} - URL: {resp.url}")

        # Try to extract error messages
        error_patterns = [
            r'<div[^>]*class=["\'][^"\']*error[^"\']*["\'][^>]*>([^<]+)',
            r'<span[^>]*class=["\'][^"\']*error[^"\']*["\'][^>]*>([^<]+)',
            r'<p[^>]*class=["\'][^"\']*error[^"\']*["\'][^>]*>([^<]+)',
        ]
        for pattern in error_patterns:
            match = re.search(pattern, resp.text, re.IGNORECASE)
            if match:
                print(f"Error: {match.group(1).strip()}")
                break

        if "login" in resp.url.lower():
            print("\n[ERROR] Login failed - still on login page")
            print("Possible causes: invalid credentials, CAPTCHA/2FA required, or bot detection")
            print("Try logging in manually from the VPS using a browser\n")
            sys.exit(1)

    print("[4/4] Accessing dashboard to collect all session cookies...")

    resp = session.get(
        "https://dinorank.com/homed/",
        impersonate="chrome_android",
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
        },
        timeout=60
    )

    print(f"[OK] Dashboard accessed ({len(session.cookies)} total cookies)")

    print("\n[EXTRACTED COOKIES]")

    cookies = {}
    cookie_list = []

    # curl_cffi can return cookies in different formats
    try:
        for name, value in session.cookies.items():
            cookies[name] = value
            cookie_list.append(f"{name}={value}")
    except AttributeError:
        try:
            for cookie in session.cookies:
                if hasattr(cookie, 'name') and hasattr(cookie, 'value'):
                    cookies[cookie.name] = cookie.value
                    cookie_list.append(f"{cookie.name}={cookie.value}")
                else:
                    cookies[str(cookie)] = str(cookie)
                    cookie_list.append(str(cookie))
        except Exception as e:
            print(f"[ERROR] Failed to extract cookies: {e}\n")
            sys.exit(1)

    print(f"Total: {len(cookies)} cookies\n")

    # Verify critical cookies
    print("Critical cookies:")
    critical = {
        'PHPSESSID': 'PHP session',
        'userId': 'User ID',
        'pass': 'Password hash',
        'comp': 'Validation token 1',
        'compx': 'Validation token 2'
    }

    critical_found = 0
    for name, desc in critical.items():
        if name in cookies:
            value_preview = cookies[name][:40] + "..." if len(cookies[name]) > 40 else cookies[name]
            print(f"  [OK] {name}: {value_preview}")
            critical_found += 1
        else:
            print(f"  [X] {name}: missing")

    print()
    if critical_found < len(critical):
        print(f"[WARNING] Only {critical_found}/{len(critical)} critical cookies found\n")

    cookie_string = ";".join(cookie_list)

    print("[UPDATING .env FILE]")

    env_file = ".env"
    if not os.path.exists(env_file):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        alt_env = os.path.join(script_dir, ".env")
        if os.path.exists(alt_env):
            env_file = alt_env
        else:
            env_file = ".env"

    if os.path.exists(env_file):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f".env.backup_{timestamp}"
        shutil.copy2(env_file, backup_file)
        print(f"[OK] Backup created: {backup_file}")

    env_lines = []
    cookie_key_found = False

    if os.path.exists(env_file):
        with open(env_file, "r", encoding="utf-8") as f:
            env_lines = f.readlines()

        for i, line in enumerate(env_lines):
            if line.strip().startswith("MASTER_COOKIES=") or line.strip().startswith("OPENID="):
                env_lines[i] = f"MASTER_COOKIES={cookie_string}\n"
                cookie_key_found = True
                break

    if not cookie_key_found:
        if env_lines and not env_lines[-1].endswith('\n'):
            env_lines.append('\n')
        env_lines.append(f"MASTER_COOKIES={cookie_string}\n")

    with open(env_file, "w", encoding="utf-8") as f:
        f.writelines(env_lines)

    print("[OK] .env file updated")

    with open("cookies_desde_vps.txt", "w", encoding="utf-8") as f:
        f.write("MASTER_COOKIES=" + cookie_string + "\n\n")
        f.write("# Extracted cookies:\n")
        for name, value in cookies.items():
            f.write(f"# {name}={value}\n")

    print(f"\n[SUMMARY]")
    print(f"  Total cookies: {len(cookies)}")
    print(f"  Critical cookies: {critical_found}/{len(critical)}")
    print(f"  Files saved: .env, cookies_desde_vps.txt")
    print(f"  Backup: .env.backup_{timestamp}\n")
    print("[NEXT STEP]")
    print("  Restart the proxy to use the new cookies:")
    print("  python3 DINORANK.py\n")

except crequests.exceptions.Timeout:
    print("\n[ERROR] Connection timeout\n")
    sys.exit(1)
except Exception as e:
    print(f"\n[ERROR] {type(e).__name__}: {str(e)}\n")
    import traceback
    traceback.print_exc()
    sys.exit(1)
