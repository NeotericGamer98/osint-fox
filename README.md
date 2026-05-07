# OSINT FOX 🦊

**Open Source Intelligence Tool** — A sleek GUI application for gathering publicly available information about targets using handles, email addresses, or phone numbers.

## Features

- **Username OSINT** — Search 35+ platforms for a username (GitHub, Reddit, Telegram, YouTube, TikTok, and more)
- **Email OSINT** — Check email validity, Gravatar profiles, EmailRep reputation, and Have I Been Pwned breach data
- **Phone OSINT** — Parse phone numbers, detect country/carrier, generate all formats
- **Export** — Save intelligence reports as PDF or plain text
- **Dark-themed UI** — Clean, modern, organized results by module category

## Installation

```bash
pip install -r requirements.txt
```

Optionally install extras for enhanced phone parsing:
```bash
pip install phonenumbers
```

## Usage

```bash
python main.py
```

1. Select a module from the sidebar (Username, Email, Phone)
2. Enter the target in the input field
3. Click **Start Scan**
4. Browse results organized by category
5. Export to PDF or TXT using the **Export Results** button

## Modules

| Module | Input | Capabilities |
|--------|-------|--------------|
| Username | Online handle | 35+ platform checks (GH, Reddit, Telegram, YT, TikTok, etc.) |
| Email | Email address | Validation, Gravatar, EmailRep, HIBP breach data |
| Phone | Phone number | Country/carrier detection, format generation, web intel links |

## Disclaimer

This tool is for **authorized security research and educational purposes only**. Users are responsible for complying with applicable laws. Unauthorized targeting of individuals may violate privacy laws.

## License

MIT
