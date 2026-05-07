import re
import json
from urllib.parse import quote
from modules.base import OSINTModule
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
    "20": {"country": "Egypt", "name": "Egypt"},
    "27": {"country": "South Africa", "name": "South Africa"},
    "54": {"country": "Argentina", "name": "Argentina"},
    "56": {"country": "Chile", "name": "Chile"},
    "57": {"country": "Colombia", "name": "Colombia"},
    "51": {"country": "Peru", "name": "Peru"},
    "63": {"country": "Philippines", "name": "Philippines"},
    "66": {"country": "Thailand", "name": "Thailand"},
    "84": {"country": "Vietnam", "name": "Vietnam"},
    "62": {"country": "Indonesia", "name": "Indonesia"},
    "60": {"country": "Malaysia", "name": "Malaysia"},
    "65": {"country": "Singapore", "name": "Singapore"},
    "64": {"country": "New Zealand", "name": "New Zealand"},
    "353": {"country": "Ireland", "name": "Ireland"},
    "45": {"country": "Denmark", "name": "Denmark"},
    "47": {"country": "Norway", "name": "Norway"},
    "358": {"country": "Finland", "name": "Finland"},
    "30": {"country": "Greece", "name": "Greece"},
    "351": {"country": "Portugal", "name": "Portugal"},
    "43": {"country": "Austria", "name": "Austria"},
    "32": {"country": "Belgium", "name": "Belgium"},
    "36": {"country": "Hungary", "name": "Hungary"},
    "40": {"country": "Romania", "name": "Romania"},
    "420": {"country": "Czech Republic", "name": "Czech Republic"},
    "38": {"country": "Ukraine", "name": "Ukraine"},
    "972": {"country": "Israel", "name": "Israel"},
    "971": {"country": "UAE", "name": "UAE"},
    "966": {"country": "Saudi Arabia", "name": "Saudi Arabia"},
    "92": {"country": "Pakistan", "name": "Pakistan"},
    "880": {"country": "Bangladesh", "name": "Bangladesh"},
    "234": {"country": "Nigeria", "name": "Nigeria"},
    "254": {"country": "Kenya", "name": "Kenya"},
    "233": {"country": "Ghana", "name": "Ghana"},
    "212": {"country": "Morocco", "name": "Morocco"},
    "216": {"country": "Tunisia", "name": "Tunisia"},
}


class PhoneModule(OSINTModule):
    def __init__(self):
        super().__init__("Phone OSINT", "\U0001F4DE", "Analyze phone numbers for carrier, location, and intelligence")

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
            progress_callback("Looking up carrier info...", 0.3)

        carrier_info = self._lookup_carrier(parsed["country_code"])
        if carrier_info:
            parsed.update(carrier_info)

        if progress_callback:
            progress_callback("Searching web for intelligence...", 0.5)

        web_intel = self._web_intel(phone_input)
        if web_intel:
            self.results["Web Intelligence"] = web_intel

        if progress_callback:
            progress_callback("Checking phone in URLs...", 0.7)

        phone_formats = self._generate_formats(parsed)
        if phone_formats:
            self.results["Possible Formats"] = phone_formats

        if progress_callback:
            progress_callback("Scan complete", 1.0)

        self.status = "complete"
        return self.results

    def _parse_number(self, raw):
        cleaned = re.sub(r'[\s\-\(\)\.\+]', '', raw)
        result = {
            "raw": raw,
            "cleaned": cleaned,
            "valid": False
        }

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

            if not result.get("valid"):
                possible = []
                for cl in [1, 2, 3]:
                    cc = digits_only[:cl]
                    if cc in CARRIER_DB:
                        possible.append(cc)
                if possible:
                    result["note"] = f"Unknown country code. Possible: {', '.join(possible)}"

        if result.get("valid") and result.get("national_number"):
            if len(result["national_number"]) < 4:
                result["valid"] = False
                result["error"] = "Number too short after country code"
            elif len(result["national_number"]) > 15:
                result["valid"] = False
                result["error"] = "Number too long after country code"

        if result.get("valid"):
            result["length"] = len(digits_only)
            possible_codes = [c for c in CARRIER_DB
                              if digits_only.startswith(c) and c != result["country_code"]]
            if possible_codes:
                result["alternate_countries"] = ", ".join(CARRIER_DB[c]["country"] for c in possible_codes)

        try:
            from phonenumbers import parse, format_number, PhoneNumberFormat, carrier, geocoder
            try:
                parsed_obj = parse(raw, None)
                result["valid"] = True
                result["e164"] = format_number(parsed_obj, PhoneNumberFormat.E164)
                result["international"] = format_number(parsed_obj, PhoneNumberFormat.INTERNATIONAL)
                result["national"] = format_number(parsed_obj, PhoneNumberFormat.NATIONAL)
                result["country_code"] = str(parsed_obj.country_code)
                result["national_number"] = str(parsed_obj.national_number)
                region = geocoder.description_for_number(parsed_obj, "en")
                if region:
                    result["region"] = region
                try:
                    carrier_name = carrier.name_for_number(parsed_obj, "en")
                    if carrier_name:
                        result["carrier"] = carrier_name
                except Exception:
                    pass
            except Exception:
                pass
        except ImportError:
            pass

        return result

    def _lookup_carrier(self, country_code):
        if country_code in CARRIER_DB:
            return {
                "country_name": CARRIER_DB[country_code]["country"],
            }
        return None

    def _web_intel(self, raw):
        results = {}

        encoded = quote(raw.strip())
        url = f"https://www.google.com/search?q={encoded}"
        results["Google Search URL"] = url

        encoded_clean = quote(re.sub(r'\D', '', raw))
        url2 = f"https://www.google.com/search?q={encoded_clean}"
        results["Google Search (digits)"] = url2

        cleaned = re.sub(r'\D', '', raw)
        if len(cleaned) >= 7:
            num_leak = f"https://www.numlookup.com/{cleaned[:10]}"
            results["NumLookup"] = num_leak

        return results

    def _generate_formats(self, parsed):
        formats = {}
        national = parsed.get("national_number", "")
        cc = parsed.get("country_code", "")

        if national and cc:
            formats["E.164"] = f"+{cc}{national}"
            formats["International"] = f"+{cc} {national}"
            formats["Dots"] = f"+{cc}.{national}"
            formats["Hyphens"] = f"+{cc}-{national}"
            formats["Plain"] = f"{cc}{national}"

        return formats
