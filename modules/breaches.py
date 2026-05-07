import hashlib
from modules.base import OSINTModule
from modules.registry import builtin_meta
from utils.network import fetch, fetch_post
from utils.apikeys import APIKeyManager


@builtin_meta("Breach Lookup", "\U0001F50D", "Search data breaches, credential leaks, and dark web sources")
class BreachModule(OSINTModule):
    def __init__(self):
        super().__init__("Breach Lookup", "\U0001F50D",
                         "Search data breaches, credential leaks, and dark web sources")
        self.keys = APIKeyManager()

    def scan(self, target, progress_callback=None):
        self.results = {}
        self.status = "scanning"
        self.results["Target"] = {"Query": target}

        is_email = "@" in target
        is_username = not is_email and not target.replace(" ", "").isdigit()

        if progress_callback:
            progress_callback("Checking Have I Been Pwned...", 0.1)
        self._check_hibp(target)

        if progress_callback:
            progress_callback("Checking breach databases...", 0.3)
        self._check_dehashed(target, is_email)

        if progress_callback:
            progress_callback("Checking IntelX...", 0.5)
        self._check_intelx(target)

        if progress_callback:
            progress_callback("Searching leak sources...", 0.7)
        self._leak_search(target, is_email)

        if progress_callback:
            progress_callback("Generating breach intelligence...", 0.9)
        self._breach_intel(target)

        if progress_callback:
            progress_callback("Scan complete", 1.0)

        self.status = "complete"
        return self.results

    def _check_hibp(self, email):
        if "@" not in email:
            self.results["Have I Been Pwned"] = {"Note": "Email required for HIBP check"}
            return
        api_key = self.keys.get("hibp")
        h = hashlib.sha1(email.lower().encode()).hexdigest().upper()
        prefix = h[:5]
        suffix = h[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        resp = fetch(url, timeout=10)
        if resp and resp.status_code == 200:
            count = 0
            for line in resp.text.splitlines():
                if line.startswith(suffix):
                    count = int(line.split(":")[1].strip())
                    break
            self.results["Have I Been Pwned"] = {
                "Email": email,
                "Breach Count": str(count),
                "Pwned": "Yes" if count > 0 else "No",
            }
            if api_key:
                try:
                    url2 = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
                    resp2 = fetch(url2, headers={"hibp-api-key": api_key}, json_response=True)
                    if resp2:
                        names = [b.get("Name", "") for b in resp2]
                        self.results["Have I Been Pwned"]["Breach Names"] = ", ".join(names[:10])
                except Exception:
                    pass
        else:
            self.results["Have I Been Pwned"] = {"Status": "Could not check"}

    def _check_dehashed(self, target, is_email):
        api_key = self.keys.get("dehashed")
        if not api_key:
            self.results["DeHashed"] = {
                "Status": "API key not configured",
                "Setup": "Add your DeHashed API key in Settings",
            }
            return
        query_type = "email" if is_email else "username"
        url = f"https://api.dehashed.com/search?query={query_type}:{target}"
        import base64
        auth = base64.b64encode(api_key.encode()).decode()
        resp = fetch(url, headers={"Accept": "application/json", "Authorization": f"Basic {auth}"},
                     json_response=True)
        if resp:
            entries = resp.get("entries", [])
            if entries:
                data = {}
                for i, entry in enumerate(entries[:10]):
                    for k, v in entry.items():
                        if v and k not in ("password", "hashed_password"):
                            data[f"{k} ({i+1})"] = str(v)[:100]
                self.results["DeHashed"] = data
                self.results["DeHashed"]["Total Results"] = str(resp.get("total", len(entries)))
            else:
                self.results["DeHashed"] = {"Results": "None found"}
        else:
            self.results["DeHashed"] = {"Status": "Query failed"}

    def _check_intelx(self, target):
        api_key = self.keys.get("intelx")
        if not api_key:
            self.results["IntelX"] = {
                "Status": "API key not configured",
                "Setup": "Add your IntelX API key in Settings",
            }
            return
        url = "https://2.intelx.io/phonebook/search"
        resp = fetch_post(url, json_data={"term": target, "maxresults": 25},
                          headers={"x-key": api_key, "Accept": "application/json",
                                   "Content-Type": "application/json"},
                          timeout=30)
        if resp and resp.status_code == 200:
            data = resp.json()
            records = data.get("records", [])
            if records:
                results = {}
                for r in records[:10]:
                    results[r.get("name", "Result")] = r.get("value", "")[:200]
                self.results["IntelX"] = results
            else:
                self.results["IntelX"] = {"Results": "None found"}
        elif resp:
            self.results["IntelX"] = {"Status": f"HTTP {resp.status_code}"}
        else:
            self.results["IntelX"] = {"Status": "Query failed"}

    def _leak_search(self, target, is_email):
        leaks = {}
        if is_email:
            leaks["Email in leaks"] = "Check hashes.org, leak-check.net, scylla.so"
        leaks["Google dork"] = f'site:pastebin.com "{target}"'
        leaks["GitHub dork"] = f'site:github.com "{target}"'
        leaks["Note"] = "Use dork URLs for manual investigation"
        self.results["Leak Search Dorks"] = leaks

    def _breach_intel(self, target):
        intel = {
            "Target": target,
            "Risk Factors": "",
            "Recommendations": [],
        }
        hibp = self.results.get("Have I Been Pwned", {})
        if isinstance(hibp, dict) and hibp.get("Breach Count", "0") != "0":
            intel["Risk Factors"] = "Email appears in known data breaches"
            intel["Recommendations"].append("Change passwords associated with this email")
            intel["Recommendations"].append("Enable 2FA on all accounts")
        dehashed = self.results.get("DeHashed", {})
        if isinstance(dehashed, dict) and "Results" not in dehashed:
            intel["Risk Factors"] = (intel.get("Risk Factors", "") + "; "
                                     "Credentials may be exposed in breach databases")
            intel["Recommendations"].append("Use unique passwords for each service")
        intel["Recommendations"] = "\n".join(intel["Recommendations"]) if intel["Recommendations"] else "No immediate action needed"
        self.results["Breach Intelligence Summary"] = intel
