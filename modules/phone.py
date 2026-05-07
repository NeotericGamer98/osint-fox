import re
import json
from urllib.parse import quote
from modules.base import OSINTModule
from modules.registry import builtin_meta
from utils.network import fetch


CARRIER_DB = {
    "1": {"country": "United States / Canada", "name": "US/Canada"},
    "44": {"country": "United Kingdom", "name": "UK"},
    "91": {"country": "India", "name": "India"},
    "86": {"country": "China", "name": "China"},
    "49": {"country": "Germany", "name": "Germany"},
    "33": {"country": "France", "name": "France"},
    "39": {"country": "Italy", "name": "Italy"},
    "34": {"country": "Spain", "name": "Spain"},
    "7": {"country": "Russia", "name": "Russia"},
    "55": {"country": "Brazil", "name": "Brazil"},
    "81": {"country": "Japan", "name": "Japan"},
    "82": {"country": "South Korea", "name": "South Korea"},
    "61": {"country": "Australia", "name": "Australia"},
    "52": {"country": "Mexico", "name": "Mexico"},
    "31": {"country": "Netherlands", "name": "Netherlands"},
    "46": {"country": "Sweden", "name": "Sweden"},
    "41": {"country": "Switzerland", "name": "Switzerland"},
    "48": {"country": "Poland", "name": "Poland"},
    "90": {"country": "Turkey", "name": "Turkey"},
    "27": {"country": "South Africa", "name": "South Africa"},
    "54": {"country": "Argentina", "name": "Argentina"},
    "56": {"country": "Chile", "name": "Chile"},
    "57": {"country": "Colombia", "name": "Colombia"},
    "63": {"country": "Philippines", "name": "Philippines"},
    "66": {"country": "Thailand", "name": "Thailand"},
    "84": {"country": "Vietnam", "name": "Vietnam"},
    "62": {"country": "Indonesia", "name": "Indonesia"},
    "65": {"country": "Singapore", "name": "Singapore"},
    "353": {"country": "Ireland", "name": "Ireland"},
    "45": {"country": "Denmark", "name": "Denmark"},
    "47": {"country": "Norway", "name": "Norway"},
    "358": {"country": "Finland", "name": "Finland"},
    "43": {"country": "Austria", "name": "Austria"},
    "972": {"country": "Israel", "name": "Israel"},
    "971": {"country": "UAE", "name": "UAE"},
    "966": {"country": "Saudi Arabia", "name": "Saudi Arabia"},
    "92": {"country": "Pakistan", "name": "Pakistan"},
    "880": {"country": "Bangladesh", "name": "Bangladesh"},
    "234": {"country": "Nigeria", "name": "Nigeria"},
    "254": {"country": "Kenya", "name": "Kenya"},
}


@builtin_meta("Phone OSINT", "\U0001F4DE", "Phone carrier, location, WhatsApp/Telegram detection")
class PhoneModule(OSINTModule):
    def __init__(self):
        super().__init__("Phone OSINT", "\U0001F4DE",
                         "Phone carrier, location, WhatsApp/Telegram detection")

    def scan(self, phone_input, progress_callback=None):
        self.results = {}
        self.status = "scanning"

        if progress_callback:
            progress_callback("Parsing phone number...", 0.1)
        parsed = self._parse_number(phone_input)
        self.results["Parsing"] = parsed

        if not parsed.get("valid", False):
            self.status = "complete"
            return self.results

        if progress_callback:
            progress_callback("Looking up carrier...", 0.25)
        carrier_info = self._lookup_carrier(parsed)
        if carrier_info:
            parsed.update(carrier_info)

        if progress_callback:
            progress_callback("Checking WhatsApp...", 0.4)
        wa = self._check_whatsapp(parsed)
        if wa:
            self.results["WhatsApp"] = wa

        if progress_callback:
            progress_callback("Checking Telegram...", 0.5)
        tg = self._check_telegram(parsed)
        if tg:
            self.results["Telegram"] = tg

        if progress_callback:
            progress_callback("Checking Signal...", 0.6)
        signal = self._check_signal(parsed)
        if signal:
            self.results["Signal"] = signal

        if progress_callback:
            progress_callback("Searching web intelligence...", 0.75)
        web = self._web_intel(phone_input, parsed)
        if web:
            self.results["Web Intelligence"] = web

        if progress_callback:
            progress_callback("Generating formats...", 0.85)
        formats = self._generate_formats(parsed)
        if formats:
            self.results["Phone Formats"] = formats

        if progress_callback:
            progress_callback("Running safety check...", 0.95)
        safety = self._safety_check(parsed)
        if safety:
            self.results["Safety Analysis"] = safety

        if progress_callback:
            progress_callback("Scan complete", 1.0)

        self.status = "complete"
        return self.results

    def _parse_number(self, raw):
        cleaned = re.sub(r'[\s\-\(\)\.]', '', raw)
        result = {"raw": raw, "cleaned": cleaned, "valid": False}
        digits_only = re.sub(r'\D', '', raw)
        if not digits_only:
            result["error"] = "No digits found"
            return result

        if digits_only.startswith("1") and len(digits_only) == 11:
            result["country_code"] = "1"
            result["national_number"] = digits_only[1:]
            result["country"] = CARRIER_DB.get("1", {}).get("country", "US/Canada")
            result["valid"] = True
            result["format_nice"] = f"+1 ({digits_only[1:4]}) {digits_only[4:7]}-{digits_only[7:]}"
        elif len(digits_only) == 10:
            result["country_code"] = "1"
            result["national_number"] = digits_only
            result["country"] = CARRIER_DB.get("1", {}).get("country", "US/Canada")
            result["valid"] = True
            result["format_nice"] = f"({digits_only[0:3]}) {digits_only[3:6]}-{digits_only[6:]}"
        else:
            for code_len in [3, 2, 1]:
                cc = digits_only[:code_len]
                if cc in CARRIER_DB:
                    result["country_code"] = cc
                    result["national_number"] = digits_only[code_len:]
                    result["country"] = CARRIER_DB[cc]["country"]
                    result["valid"] = True
                    result["format_nice"] = f"+{cc} {result['national_number']}"
                    break

        if result.get("valid") and result.get("national_number"):
            if len(result["national_number"]) < 4:
                result["valid"] = False
                result["error"] = "Number too short"
            elif len(result["national_number"]) > 15:
                result["valid"] = False
                result["error"] = "Number too long"

        if result.get("valid"):
            result["length"] = len(digits_only)
            try:
                import phonenumbers as pn
                parsed_obj = pn.parse(raw, None)
                result["e164"] = pn.format_number(parsed_obj, pn.PhoneNumberFormat.E164)
                result["international"] = pn.format_number(parsed_obj, pn.PhoneNumberFormat.INTERNATIONAL)
                result["national"] = pn.format_number(parsed_obj, pn.PhoneNumberFormat.NATIONAL)
                result["country_code"] = str(parsed_obj.country_code)
                result["national_number"] = str(parsed_obj.national_number)
                try:
                    region = pn.geocoder.description_for_number(parsed_obj, "en")
                    if region:
                        result["region"] = region
                except Exception:
                    pass
                try:
                    cname = pn.carrier.name_for_number(parsed_obj, "en")
                    if cname:
                        result["carrier"] = cname
                except Exception:
                    pass
            except ImportError:
                pass
            except Exception:
                pass

        return result

    def _lookup_carrier(self, parsed):
        cc = parsed.get("country_code", "")
        if cc in CARRIER_DB:
            return {"country_name": CARRIER_DB[cc]["country"]}
        return None

    def _check_whatsapp(self, parsed):
        e164 = parsed.get("e164", "")
        if not e164:
            e164 = f"+{parsed.get('country_code', '')}{parsed.get('national_number', '')}"
        url = f"https://wa.me/{e164.lstrip('+')}"
        resp = fetch(url, allow_redirects=False)
        if resp and resp.status_code == 200:
            return {"WhatsApp URL": url, "Status": "WhatsApp account likely exists"}
        elif resp and resp.status_code == 302:
            loc = resp.headers.get("location", "")
            if "send" in loc:
                return {"WhatsApp URL": url, "Status": "WhatsApp account exists"}
        return {"WhatsApp URL": url, "Status": "Check manually (WhatsApp redirects to app)"}

    def _check_telegram(self, parsed):
        nat = parsed.get("national_number", "")
        cc = parsed.get("country_code", "")
        tg_url = f"https://t.me/+{cc}{nat}" if cc and nat else None
        if tg_url:
            resp = fetch(tg_url, allow_redirects=False)
            exists = resp is not None and resp.status_code == 200
            if exists:
                return {"Telegram URL": tg_url, "Status": "Telegram account likely exists"}
        return {"Telegram Search": f"Search for +{cc}{nat} on Telegram app", "Status": "Check manually"}

    def _check_signal(self, parsed):
        e164 = parsed.get("e164", "")
        if e164:
            return {
                "Signal URL": f"https://signal.me/#p/{e164}",
                "Status": "Open Signal URL to check if account exists",
            }
        return None

    def _web_intel(self, raw, parsed):
        results = {}
        encoded = quote(raw.strip())
        results["Google Search"] = f"https://www.google.com/search?q={encoded}"
        cleaned = re.sub(r'\D', '', raw)
        encoded_clean = quote(cleaned)
        results["Google (digits)"] = f"https://www.google.com/search?q={encoded_clean}"
        if parsed.get("e164"):
            e164 = parsed["e164"]
            results["Truecaller"] = f"https://www.truecaller.com/search/{e164.lstrip('+')}"
            results["NumLookup"] = f"https://www.numlookup.com/{e164.lstrip('+')}"
        return results

    def _generate_formats(self, parsed):
        formats = {}
        nat = parsed.get("national_number", "")
        cc = parsed.get("country_code", "")
        if nat and cc:
            formats["E.164"] = f"+{cc}{nat}"
            formats["International"] = f"+{cc} {nat}"
            formats["Dots"] = f"+{cc}.{nat}"
            formats["Hyphens"] = f"+{cc}-{nat}"
            formats["Plain"] = f"{cc}{nat}"
            formats["Local"] = nat
            if len(nat) == 10:
                formats["US Format"] = f"({nat[:3]}) {nat[3:6]}-{nat[6:]}"
        return formats

    def _safety_check(self, parsed):
        result = {}
        cc = parsed.get("country_code", "")
        nat = parsed.get("national_number", "")
        if cc == "1" and len(nat or "") == 10:
            area = nat[:3]
            spam_areas = ["800", "888", "877", "866", "855", "844", "900"]
            if area in spam_areas:
                result["Toll-Free/High Risk"] = f"Area code {area} is toll-free/premium"
            result["Area Code"] = area
        result["Note"] = "Use Truecaller or similar for spam call identification"
        return result
