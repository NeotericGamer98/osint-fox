STRINGS = {
    "en": {
        "app_title": "OSINT FOX",
        "app_subtitle": "Open Source Intelligence Tool",
        "modules": "MODULES",
        "username": "Username",
        "email": "Email",
        "phone": "Phone",
        "domain": "Domain",
        "social": "Social Analyzer",
        "image": "Image OSINT",
        "breaches": "Breach Lookup",
        "geo": "Geolocation",
        "enter_target": "Enter target...",
        "start_scan": "Start Scan",
        "clear": "Clear",
        "export": "Export Results",
        "results": "RESULTS",
        "settings": "Settings",
        "about": "About",
        "ready": "Ready",
        "scanning": "Scanning...",
        "scan_complete": "Scan complete",
        "no_results": "No results to export.",
        "export_title": "Export Intelligence Report",
        "export_pdf": "Export as PDF",
        "export_txt": "Export as Text",
        "export_csv": "Export as CSV",
        "export_json": "Export as JSON",
        "export_html": "Export as HTML",
        "dark_theme": "Dark Theme",
        "light_theme": "Light Theme",
        "theme": "Theme",
        "proxy": "Proxy Settings",
        "api_keys": "API Keys",
        "sessions": "Sessions",
        "save_session": "Save Session",
        "load_session": "Load Session",
        "clear_results": "Clear Results",
        "confirm_clear": "Clear all results?",
        "error": "Error",
        "warning": "Warning",
        "info": "Information",
        "close": "Close",
    },
}

_current_lang = "en"


def set_lang(lang):
    global _current_lang
    if lang in STRINGS:
        _current_lang = lang


def get(key):
    return STRINGS.get(_current_lang, {}).get(key, key)


def available_langs():
    return list(STRINGS.keys())
