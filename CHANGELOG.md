# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-02-06

### Added
- Session keepalive system to maintain active session with periodic pings (every 4.5h)
- Reactive cookie renewal on detection of expired cookies (401/403)
- Thread-safe coordination between keepalive and cookie renewal
- Smart rate limiting (600 req/min dynamic, 2000 req/min static)
- Intelligent caching for static resources (5-minute TTL, LRU eviction)
- Exponential backoff retry logic for 429 rate limit errors
- Content filtering via CSS injection to hide promotional banners
- Cloudflare-ready nginx configuration
- HMAC-SHA256 token authentication system
- Comprehensive logging with structured output

### Changed
- **Code cleanup**: Removed 338 lines of verbose comments and redundant code (15% reduction)
- **Documentation**: Restructured README.md for better GitHub presentation (297→246 lines)
- **Comments**: Standardized to English for international developer audience
- **Docstrings**: Simplified to concise, action-oriented descriptions
- **Log messages**: Made more professional and less verbose
- **Keepalive interval**: Changed default from 4.5h to 0.25h (15 minutes) for cookies that expire every 30 minutes
- Organized project structure: created `/docs`, `/config`, `/examples` folders
- Moved nginx configuration to `/config` folder
- Moved documentation files to `/docs` folder

### Fixed
- Performance issues caused by heavy regex patterns (now uses CSS-only filtering)
- Timeout issues (increased to 180s)
- URL rewriting for localhost and production environments
- WordPress/Jetpack CDN image optimization conflicts
- Cookie parsing for various formats (OPENID, MASTER_COOKIES)
- Thread safety issues between keepalive and renewal processes

### Removed
- Redundant section headers (e.g., "# Configure logging", "# Rate limiting")
- Obvious inline comments (e.g., `# 5 hours`, `# 5 minutes cache`)
- Verbose docstrings with unnecessary Args/Returns sections
- Tutorial-style comments in login script
- Unnecessary files: `CONTEXTO.MD`, `nul`, `.env` from examples folder
- Excessive separator lines in logging output

### Security
- HMAC-SHA256 token signing (replaces weak Caesar cipher)
- SSL verification enabled by default
- Secure CORS with origin whitelist
- Rate limiting protection against brute-force attacks
- Secure cookie attributes (`__Host-` prefix, Strict SameSite)

## [1.0.0] - 2025-XX-XX

### Added
- Initial release
- Basic reverse proxy functionality for DinoRank
- Cookie-based session management
- PHP token generation and validation
- 6-hour automatic cookie renewal cycle (via supervisor)
- Basic error handling and logging
- `.env` configuration support

[2.0.0]: https://github.com/your-user/dinorank-proxy/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/your-user/dinorank-proxy/releases/tag/v1.0.0
