# OSINT FOX 🦊

**Open Source Intelligence Tool v1.1** — A sleek GUI application for gathering publicly available information about targets using handles, email addresses, phone numbers, domains, images, and more.

## Features

### Modules
| Module | Input | Capabilities |
|--------|-------|-------------|
| **Username** 🕵️ | Online handle | 40+ platform searches (GitHub, Reddit, Telegram, YouTube, TikTok, etc.) |
| **Email** ✉️ | Email address | Validation, Gravatar, EmailRep reputation, HIBP breaches, SMTP verification |
| **Phone** 📞 | Phone number | Country/carrier detection, WhatsApp/Telegram/Signal check, format generation |
| **Domain** 🌐 | Domain/IP | DNS records, WHOIS, SSL certs, subdomain enumeration, IP intelligence |
| **Social Analyzer** 👥 | Username | Cross-platform bio consistency, metadata comparison, correlation analysis |
| **Image** 🖼️ | URL/file path | EXIF metadata, perceptual hashing (aHash/dHash/pHash), reverse image search |
| **Breach Lookup** 🔍 | Email/username | HIBP, DeHashed, IntelX, dork generation, breach intelligence summary |
| **Geolocation** 🌍 | IP/domain | IP geolocation, timezone, map links, network intelligence |

### Interface
- **Dark/Light theme toggle** 🌓
- **Tabbed scan sessions** — Run multiple scans, compare results
- **Session save/load** — Save and reload `.osint` session files
- **Plugin system** — Auto-detect modules in `modules/plugins/`

### Export
5 formats: **PDF**, **TXT**, **CSV**, **JSON**, **HTML**

### Technical
- Per-platform rate limiting with caching
- Proxy/Tor support (SOCKS5)
- API key management dialog
- Headless CLI mode for automation

## Installation

```bash
pip install -r requirements.txt
```

Optional enhancements:
```bash
pip install python-whois pytz phonenumbers
```

## Usage

### GUI Mode
```bash
python main.py
```

### CLI Mode (headless)
```bash
python main.py --cli --module username --target johndoe
python main.py --cli --module email --target user@example.com --format json --output report.json
python main.py --cli --module domain --target example.com --proxy socks5://127.0.0.1:9050
```

## Module Descriptions

### Username OSINT
Searches 40+ platforms for account presence including GitHub, GitLab, Reddit, Telegram, YouTube, TikTok, Medium, Dev.to, Keybase, HackerNews, Pinterest, Replit, Pastebin, BitBucket, Twitch, Steam, Flickr, VK, Snapchat, Patreon, and more.

### Email OSINT
Validates email format, checks MX records, performs SMTP verification, looks up Gravatar profiles, queries EmailRep.io for reputation, checks Have I Been Pwned for breach data, and correlates with social platforms.

### Phone OSINT
Parses phone numbers using multiple algorithms, detects country and carrier, checks for WhatsApp/Telegram/Signal accounts, generates multiple number formats, and provides safety/spam analysis.

### Domain OSINT
Resolves DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA), checks SSL certificates, performs WHOIS lookups (via library or scraping), enumerates common subdomains, inspects web headers, and generates IP intelligence links.

### Social Analyzer
Gathers bios and metadata from discovered social profiles, analyzes consistency across platforms, categorizes platform presence, and generates correlation insights.

### Image OSINT
Downloads or reads image files, extracts EXIF metadata (including GPS coordinates), generates perceptual image hashes (aHash, dHash, pHash) for similarity matching, and creates reverse image search URLs.

### Breach Lookup
Checks Have I Been Pwned for password breaches, queries DeHashed and IntelX APIs for credential leaks, generates Google/GitHub dorks for manual investigation, and provides breach intelligence recommendations.

### Geolocation
Resolves targets to IP addresses, performs geolocation lookups via ip-api.com and ipinfo.io, determines timezone and local time, generates Google Maps/OpenStreetMap links, and provides network intelligence data.

## Configuration

### API Keys
Configure API keys in Settings > API Keys for enhanced scanning:
- Shodan, Censys, Have I Been Pwned, DeHashed, IntelX, EmailRep, VirusTotal

### Proxy/Tor
Configure proxy in Settings > Proxy (e.g. `socks5://127.0.0.1:9050` for Tor).

## Plugin System

Place Python files in `modules/plugins/` with classes that inherit from `OSINTModule` and use the `@builtin_meta` decorator. They auto-load on next launch.

## Disclaimer

This tool is for **authorized security research and educational purposes only**. Users are responsible for complying with applicable laws. Unauthorized targeting of individuals may violate privacy laws.

## License

MIT
