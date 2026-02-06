# DinoRank Proxy

> Smart reverse proxy for DinoRank with automatic session management, keepalive, and content filtering.

## Features

- **Reverse Proxy** - Access DinoRank through your own domain
- **Auto Cookie Renewal** - Automatic renewal every 6 hours
- **Session Keepalive** - Periodic pings (every 4.5h) to keep session alive
- **Reactive Renewal** - Detects expired cookies (401/403) and renews automatically
- **Content Filtering** - Hides DinoRank promotional banners
- **Rate Limiting** - Protection against abuse (600 req/min dynamic, 2000 req/min static)
- **Smart Caching** - 5-minute cache for static resources
- **Retry with Backoff** - Automatic handling of rate limits (429) with exponential backoff
- **Thread-Safe** - Coordinated keepalive and cookie renewal

## Quick Start

### Prerequisites

- Python 3.8+
- DinoRank account
- VPS or server (recommended for automatic cookie extraction)

### Installation

```bash
# Clone repository
git clone https://github.com/your-user/dinorank-proxy.git
cd dinorank-proxy

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
nano .env  # Edit with your credentials
```

### Configuration

Edit `.env` with your DinoRank credentials:

```bash
# DinoRank credentials
DINORANK_EMAIL=your_email@example.com
DINORANK_PASSWORD=your_password

# Session cookies (extract manually from browser)
OPENID=your_cookies_here_separated_by_semicolons

# Proxy port
PORT_DINORANK=4040

# Keepalive (keep session active)
KEEPALIVE_ENABLED=true
KEEPALIVE_INTERVAL_HOURS=4.5
KEEPALIVE_ENDPOINT=/homed/
```

### Extract Cookies Manually

⚠️ **Important**: Automatic login doesn't work due to DinoRank's captcha. Extract cookies manually:

**Chrome/Edge:**
1. Open DinoRank and login
2. Press F12 > Application > Cookies > dinorank.com
3. Right-click any cookie > "Copy all as Header String"
4. Paste the result in `OPENID=` in your `.env`

**Firefox:**
1. F12 > Storage > Cookies > https://dinorank.com
2. Select all cookies and copy
3. Format as: `cookie1=value1;cookie2=value2;...`
4. Paste in `OPENID=` in your `.env`

## Usage

### Run Proxy Only

```bash
python3 DINORANK.py
```

Proxy starts at `http://localhost:4040` with keepalive active.

### Run with Supervisor (Recommended)

```bash
python3 auto_supervisor.py
```

The supervisor:
- Renews cookies every 6 hours
- Automatically restarts proxy
- Monitors process (restarts if it crashes)
- Keepalive maintains session between renewals

### View Logs

```bash
tail -f supervisor.log
```

## Architecture

```
┌─────────────────────┐
│  auto_supervisor.py │  ← Renews cookies every 6h, restarts proxy
└──────────┬──────────┘
           │
           ↓
    ┌──────────────┐
    │ DINORANK.py  │  ← Main proxy (Flask + curl-cffi)
    └──────┬───────┘
           │
   ┌───────┴────────┐
   │                │
   ↓                ↓
┌─────────────┐  ┌──────────────┐
│ Keepalive   │  │ CookieMonitor│  ← Reactive renewal on 401/403
│ Thread      │──│              │
│ (4.5h ping) │  │ (5min cd)    │
└─────────────┘  └──────────────┘
```

## Configuration

### Keepalive

```bash
KEEPALIVE_ENABLED=true           # Enable/disable keepalive
KEEPALIVE_INTERVAL_HOURS=4.5     # Interval between pings (default: 4.5h)
KEEPALIVE_ENDPOINT=/homed/       # Endpoint to ping
```

**How it works:**
- Makes GET to `/homed/` every 4.5 hours
- Automatically detects expired cookies (401/403)
- Triggers renewal if needed
- Integrates with `cookie_monitor.py` to avoid conflicts

### Rate Limiting

```python
MAX_REQUESTS_PER_MINUTE = 600           # Dynamic requests
MAX_REQUESTS_PER_MINUTE_STATIC = 2000   # Static resources (CSS, JS, etc)
```

### Cache

```python
CACHE_TTL = 300         # 5 minutes
CACHE_MAX_SIZE = 1000   # Max items in cache
```

## Project Structure

```
.
├── DINORANK.py                      # Main proxy server
├── auto_supervisor.py               # Supervisor for 6h renewal cycle
├── cookie_monitor.py                # Expired cookie monitor
├── login_y_extraer_cookies.py       # Login script (doesn't work due to captcha)
├── dinorank.php                     # PHP authentication integration
├── nginx_dinorank.conf              # Nginx configuration example
├── .env                             # Configuration (DO NOT COMMIT)
├── .env.example                     # Configuration template
├── requirements.txt                 # Python dependencies
└── README.md                        # This file
```

## Security

**IMPORTANT:**
- ⚠️ **NEVER** upload your `.env` file to GitHub
- ⚠️ **NEVER** upload `cookies_*.txt` or `.log` files
- ⚠️ The `.gitignore` is configured to protect you

DinoRank cookies have full access to your account. Keep them secure.

## Troubleshooting

### Pages load slowly
**Solution**: Already optimized - only uses CSS to hide banners.

### Cookies expire quickly
**Solution**: Keepalive is enabled (pings every 4.5h).

### Automatic login doesn't work
**Solution**: DinoRank has captcha/2FA/bot detection. Extract cookies manually from browser.

### Error 401/403 when using proxy
**Solution**:
1. Extract fresh cookies manually from browser
2. Update `OPENID=` in `.env`
3. Restart proxy

### Timeout errors
**Solution**: Timeouts already configured to 180s.

## Monitoring

### Keepalive Logs

```
Keepalive thread started
  Interval: 4.5 hours
  Endpoint: /homed/
Next keepalive ping in 4.52 hours
✓ Keepalive ping successful (200, 234ms)
```

### Renewal Logs

```
⚠ Keepalive detected expired cookies (401)
→ Triggering auto-renewal of cookies...
✓ Cookies renewed, keepalive resumed
```

## Contributing

Contributions are welcome! Please:
1. Fork the project
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is open source and available under the MIT License.

## Disclaimer

This proxy is for personal and educational use. Ensure you comply with DinoRank's terms of service when using this tool.

---


**DEVDOP- JOSE MICHEL**

**Developed with ❤️ for the SEO community**
