import socket
import ssl
from datetime import datetime

from modules.base import OSINTModule
from modules.registry import builtin_meta
from utils.network import fetch, rate_limit
from utils.cache import ScanCache

cache = ScanCache()


@builtin_meta("Domain OSINT", "\U0001F310", "WHOIS, DNS, subdomains, SSL, and IP intelligence")
class DomainModule(OSINTModule):
    def __init__(self):
        super().__init__("Domain OSINT", "\U0001F310",
                         "WHOIS, DNS, subdomains, SSL, and IP intelligence")

    def scan(self, target, progress_callback=None):
        self.results = {}
        self.status = "scanning"
        target = target.strip().lower()
        if target.startswith("http://") or target.startswith("https://"):
            from urllib.parse import urlparse
            target = urlparse(target).netloc or target
        target = target.split("/")[0].split(":")[0]
        self.results["Target"] = {"Domain": target}

        if progress_callback:
            progress_callback("Resolving DNS records...", 0.1)
        self._dns_lookup(target)

        if progress_callback:
            progress_callback("Checking SSL certificate...", 0.3)
        self._ssl_check(target)

        if progress_callback:
            progress_callback("Performing WHOIS lookup...", 0.5)
        self._whois_lookup(target)

        if progress_callback:
            progress_callback("Enumerating subdomains...", 0.7)
        self._subdomain_enum(target)

        if progress_callback:
            progress_callback("Checking web technologies...", 0.85)
        self._web_tech(target)

        if progress_callback:
            progress_callback("Checking IP reputation...", 0.95)
        self._ip_reputation(target)

        if progress_callback:
            progress_callback("Scan complete", 1.0)

        self.status = "complete"
        return self.results

    def _dns_lookup(self, domain):
        records = {}
        for qtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
            try:
                answers = socket.getaddrinfo(domain, 0)
                if qtype == "A":
                    ips = list(set(a[4][0] for a in answers if a[0] == socket.AF_INET))
                    if ips:
                        records[qtype] = ips
            except Exception:
                pass
        try:
            import dns.resolver
            for qtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
                try:
                    answers = dns.resolver.resolve(domain, qtype, lifetime=10)
                    if qtype in ("MX",):
                        records[qtype] = [str(r.exchange) for r in answers]
                    elif qtype == "SOA":
                        for r in answers:
                            records[qtype] = str(r.mname)
                    else:
                        records[qtype] = [str(r) for r in answers]
                except Exception:
                    pass
        except ImportError:
            pass
        if records:
            self.results["DNS Records"] = records
        else:
            self.results["DNS Records"] = {"Status": "Could not resolve"}

        if "A" in records:
            self.results["IP Addresses"] = {"IPv4": ", ".join(records["A"][:5])}

    def _ssl_check(self, domain):
        for port in (443, 8443):
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((domain, port), timeout=8) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        if cert:
                            self.results[f"SSL Certificate (port {port})"] = {
                                "Issuer": dict(cert.get("issuer", [])).get("organizationName", "N/A"),
                                "Subject": dict(cert.get("subject", [])).get("commonName", ""),
                                "Valid From": cert.get("notBefore", ""),
                                "Valid Until": cert.get("notAfter", ""),
                                "SAN": ", ".join(cert.get("subjectAltName", [("", "")])[0]) if cert.get("subjectAltName") else "N/A",
                                "Serial": hex(cert.get("serialNumber", 0)),
                            }
                            return
            except Exception:
                pass
        self.results["SSL Certificate"] = {"Status": "No SSL or connection failed"}

    def _whois_lookup(self, domain):
        try:
            import whois
            rate_limit("whois", 2.0)
            w = whois.whois(domain)
            data = {}
            if w.name: data["Registrant Name"] = w.name
            if w.org: data["Organization"] = w.org
            if w.registrar: data["Registrar"] = w.registrar
            if w.creation_date:
                cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                data["Created"] = str(cd)
            if w.expiration_date:
                ed = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                data["Expires"] = str(ed)
            if w.name_servers:
                data["Name Servers"] = ", ".join(w.name_servers[:5])
            if w.emails:
                data["Emails"] = ", ".join(w.emails if isinstance(w.emails, list) else [w.emails])
            if w.country: data["Country"] = w.country
            if w.city: data["City"] = w.city
            if data:
                self.results["WHOIS"] = data
                return
        except ImportError:
            pass
        except Exception:
            pass

        url = f"https://www.whois.com/whois/{domain}"
        resp = fetch(url)
        if resp and resp.status_code == 200:
            import re
            text = resp.text
            rows = re.findall(r'<div[^>]*class="df-row"[^>]*>.*?<div[^>]*class="df-label"[^>]*>(.*?)</div>.*?<div[^>]*class="df-value"[^>]*>(.*?)</div>', text, re.DOTALL)
            data = {}
            for label, value in rows[:10]:
                clean_label = re.sub(r'<[^>]+>', '', label).strip()
                clean_value = re.sub(r'<[^>]+>', '', value).strip()
                if clean_label and clean_value:
                    data[clean_label] = clean_value
            if data:
                self.results["WHOIS (scraped)"] = data

    def _subdomain_enum(self, domain):
        common = ["www", "mail", "admin", "api", "blog", "dev", "test", "staging",
                   "cdn", "static", "assets", "img", "images", "docs", "help",
                   "support", "forum", "community", "shop", "store", "m", "mobile",
                   "app", "beta", "demo", "stage", "prod", "backup", "status",
                   "webmail", "smtp", "pop", "imap", "ftp", "ssh", "git", "svn",
                   "jenkins", "jira", "confluence", "wiki", "secure", "login",
                   "auth", "sso", "portal", "my", "dashboard"]
        found = []
        ck = cache.get(f"subdomains_{domain}", max_age=86400)
        if ck:
            found = ck
        else:
            import concurrent.futures
            def check_sub(sub):
                sub_domain = f"{sub}.{domain}"
                try:
                    socket.getaddrinfo(sub_domain, 0)
                    return sub_domain
                except Exception:
                    return None
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
                futures = {ex.submit(check_sub, s): s for s in common}
                for f in concurrent.futures.as_completed(futures):
                    result = f.result()
                    if result:
                        found.append(result)
            cache.set(f"subdomains_{domain}", found)
        if found:
            subs = found[:20] if len(found) > 20 else found
            self.results["Subdomains Found"] = {"Subdomains": ", ".join(subs)}
            self.results["Subdomains Found"]["Total"] = str(len(found))
        else:
            self.results["Subdomains"] = {"Status": "None found"}

    def _web_tech(self, domain):
        try:
            url = f"https://{domain}"
            resp = fetch(url, timeout=10)
            if resp:
                headers = dict(resp.headers)
                info = {}
                sv = headers.get("Server", "")
                if sv: info["Server"] = sv
                pw = headers.get("X-Powered-By", "")
                if pw: info["X-Powered-By"] = pw
                ct = headers.get("Content-Type", "")
                if ct: info["Content-Type"] = ct
                if info:
                    self.results["Web Headers"] = info
        except Exception:
            pass

    def _ip_reputation(self, domain):
        ips = self.results.get("IP Addresses", {})
        if "IPv4" in ips:
            ip = ips["IPv4"].split(",")[0].strip()
            self.results["IP Intelligence"] = {
                "IP Address": ip,
                "Shodan": f"https://www.shodan.io/host/{ip}",
                "Censys": f"https://search.censys.io/hosts/{ip}",
                "VirusTotal": f"https://www.virustotal.com/gui/ip-address/{ip}",
                "AbuseIPDB": f"https://www.abuseipdb.com/check/{ip}",
            }
