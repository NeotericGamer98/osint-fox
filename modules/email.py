import re
import dns.resolver
from modules.base import OSINTModule
from utils.network import fetch, check_gravatar, check_emailrep, check_hibp, get_gravatar_hash


class EmailModule(OSINTModule):
    def __init__(self):
        super().__init__("Email OSINT", "\u2709", "Investigate email addresses for breaches, profiles, and metadata")

    def scan(self, email, progress_callback=None):
        self.results = {}
        self.status = "scanning"

        email = email.strip()

        if progress_callback:
            progress_callback("Validating email...", 0.1)

        validation = self._validate_email(email)
        self.results["Validation"] = validation

        if not validation.get("valid", False):
            self.results["Analysis"] = {"Status": "Invalid email address format"}
            self.status = "complete"
            return self.results

        if progress_callback:
            progress_callback("Checking Gravatar...", 0.3)

        gravatar = check_gravatar(email)
        if gravatar["exists"]:
            gdata = {"Avatar URL": gravatar.get("avatar_url", "")}
            if gravatar.get("display_name"):
                gdata["Display Name"] = gravatar["display_name"]
            if gravatar.get("about"):
                gdata["About"] = gravatar["about"]
            if gravatar.get("location"):
                gdata["Location"] = gravatar["location"]
            if gravatar.get("urls"):
                gdata["URLs"] = ", ".join(u.get("value", "") for u in gravatar["urls"] if u.get("value"))
            self.results["Gravatar Profile"] = gdata
        else:
            self.results["Gravatar Profile"] = {"Status": "No Gravatar found"}

        if progress_callback:
            progress_callback("Checking email reputation...", 0.5)

        emailrep = check_emailrep(email)
        if emailrep is not None:
            rep_data = {}
            if "reputation" in emailrep:
                rep_data["Reputation"] = emailrep["reputation"]
            if "suspicious" in emailrep:
                rep_data["Suspicious"] = "Yes" if emailrep["suspicious"] else "No"
            if "blacklisted" in emailrep:
                rep_data["Blacklisted"] = "Yes" if emailrep["blacklisted"] else "No"
            if "malicious_activity" in emailrep:
                rep_data["Malicious Activity"] = "Yes" if emailrep["malicious_activity"] else "No"
            if "credentials_leaked" in emailrep:
                rep_data["Credentials Leaked"] = "Yes" if emailrep["credentials_leaked"] else "No"
            if "data_breach" in emailrep:
                rep_data["Data Breach"] = "Yes" if emailrep["data_breach"] else "No"
            if "first_seen" in emailrep:
                rep_data["First Seen"] = emailrep["first_seen"]
            if "last_seen" in emailrep:
                rep_data["Last Seen"] = emailrep["last_seen"]
            if "domain_exists" in emailrep:
                rep_data["Domain Exists"] = "Yes" if emailrep["domain_exists"] else "No"
            if "domain_reputation" in emailrep:
                rep_data["Domain Reputation"] = emailrep["domain_reputation"]
            if "details" in emailrep and emailrep["details"]:
                details = emailrep["details"]
                if "profiles" in details:
                    rep_data["Profiles Found"] = ", ".join(details["profiles"])
                if "websites" in details:
                    rep_data["Websites"] = ", ".join(details["websites"])
            self.results["EmailRep.io Analysis"] = rep_data

        if progress_callback:
            progress_callback("Checking data breaches...", 0.7)

        breach_count = check_hibp(email)
        if breach_count is not None:
            self.results["Data Breaches (HIBP)"] = {
                "Email": email,
                "Breach Count (Pwned)": str(breach_count),
                "Note": "This email appears in known data breaches" if breach_count > 0 else "No known breaches found"
            }
        else:
            self.results["Data Breaches (HIBP)"] = {
                "Status": "Could not check (rate limited or unavailable)"
            }

        if progress_callback:
            progress_callback("Checking email in URLs...", 0.85)

        url_checks = self._check_email_urls(email)
        if url_checks:
            self.results["Web Presence"] = url_checks

        if progress_callback:
            progress_callback("Scan complete", 1.0)

        self.status = "complete"
        return self.results

    def _validate_email(self, email):
        result = {"email": email, "valid": False}

        pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            result["error"] = "Invalid email format"
            return result

        result["format"] = "Valid"
        local, domain = email.split("@")

        result["local_part"] = local
        result["domain"] = domain
        result["tld"] = domain.split(".")[-1] if "." in domain else ""

        spammy_domains = ["mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
                          "throwaway.email", "yopmail.com", "trashmail.com"]
        if domain.lower() in spammy_domains:
            result["disposable"] = True
            result["warning"] = "Disposable/temporary email domain detected"
        else:
            result["disposable"] = False

        valid_chars = len(re.findall(r'[a-zA-Z]', local))
        if valid_chars == 0 and len(local) > 0:
            result["likely_auto"] = True
            result["note"] = "Local part contains no letters (possibly auto-generated)"

        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=10)
            result["mx_records"] = [str(x.exchange) for x in answers]
            result["has_mx"] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout,
                dns.resolver.LifetimeTimeout, dns.resolver.NoNameservers):
            result["has_mx"] = False
            result["warning"] = "Domain has no MX records (may not accept email)"
        except ImportError:
            result["has_mx"] = "dnspython not installed - MX check skipped"

        result["valid"] = True
        return result

    def _check_email_urls(self, email):
        results = {}
        local, domain = email.split("@")
        h = get_gravatar_hash(email)

        gravatar_url = f"https://www.gravatar.com/{h}.json"
        resp = fetch(gravatar_url, json_response=True)
        if resp and resp.get("entry"):
            results["Gravatar Profiles"] = f"Found profiles on Gravatar"

        return results if results else None
