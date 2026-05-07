import re
import smtplib
import dns.resolver
from modules.base import OSINTModule
from modules.registry import builtin_meta
from utils.network import fetch, check_gravatar, check_emailrep, check_hibp, get_gravatar_hash
from utils.apikeys import APIKeyManager


@builtin_meta("Email OSINT", "\u2709", "Email validation, Gravatar, EmailRep, HIBP breaches, SMTP verify")
class EmailModule(OSINTModule):
    def __init__(self):
        super().__init__("Email OSINT", "\u2709",
                         "Email validation, Gravatar, EmailRep, HIBP breaches, SMTP verify")
        self.keys = APIKeyManager()

    def scan(self, email, progress_callback=None):
        self.results = {}
        self.status = "scanning"
        email = email.strip()

        if progress_callback:
            progress_callback("Validating email...", 0.05)

        validation = self._validate_email(email)
        self.results["Validation"] = validation

        if not validation.get("valid", False):
            self.results["Analysis"] = {"Status": "Invalid email address format"}
            self.status = "complete"
            return self.results

        if progress_callback:
            progress_callback("Checking Gravatar...", 0.15)
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
            if gravatar.get("accounts"):
                accounts = []
                for acct in gravatar["accounts"]:
                    name = acct.get("display", acct.get("shortname", ""))
                    url2 = acct.get("url", "")
                    if name and url2:
                        accounts.append(f"{name} ({url2})")
                if accounts:
                    gdata["Connected Accounts"] = "\n".join(accounts[:5])
            self.results["Gravatar Profile"] = gdata
        else:
            self.results["Gravatar Profile"] = {"Status": "No Gravatar found"}

        if progress_callback:
            progress_callback("Checking email reputation...", 0.3)
        emailrep_key = self.keys.get("emailrep")
        emailrep = check_emailrep(email, emailrep_key)
        if emailrep is not None:
            rep_data = {}
            for k in ("reputation", "suspicious", "blacklisted", "malicious_activity",
                       "credentials_leaked", "data_breach", "first_seen", "last_seen",
                       "domain_exists", "domain_reputation"):
                v = emailrep.get(k)
                if v is not None:
                    label = k.replace("_", " ").title()
                    rep_data[label] = str(v) if not isinstance(v, bool) else ("Yes" if v else "No")
            if "details" in emailrep and emailrep["details"]:
                details = emailrep["details"]
                if "profiles" in details:
                    rep_data["Profiles Found"] = ", ".join(details["profiles"])
                if "websites" in details:
                    rep_data["Websites"] = ", ".join(details["websites"])
            self.results["EmailRep.io Analysis"] = rep_data

        if progress_callback:
            progress_callback("Checking data breaches...", 0.45)
        hibp_key = self.keys.get("hibp")
        breach_count = check_hibp(email, hibp_key)
        if breach_count is not None:
            self.results["Data Breaches (HIBP)"] = {
                "Email": email,
                "Breach Count": str(breach_count),
                "Pwned": "Yes" if breach_count > 0 else "No",
            }
        else:
            self.results["Data Breaches (HIBP)"] = {"Status": "Could not check"}

        if progress_callback:
            progress_callback("Performing SMTP verification...", 0.6)
        if validation.get("has_mx") == True:
            smtp_result = self._smtp_verify(email, validation.get("mx_records", []))
            if smtp_result:
                self.results["SMTP Verification"] = smtp_result

        if progress_callback:
            progress_callback("Correlating email with social accounts...", 0.75)
        self._social_correlation(email)

        if progress_callback:
            progress_callback("Searching web presence...", 0.9)
        self._web_presence(email)

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

        disposable = ["mailinator.com", "guerrillamail.com", "10minutemail.com",
                       "tempmail.com", "throwaway.email", "yopmail.com", "trashmail.com",
                       "temp-mail.org", "mailnesia.com"]
        if domain.lower() in disposable:
            result["disposable"] = True
            result["warning"] = "Disposable/temporary email domain detected"
        else:
            result["disposable"] = False

        valid_chars = len(re.findall(r'[a-zA-Z]', local))
        if valid_chars == 0 and len(local) > 0:
            result["likely_auto"] = True

        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=10)
            result["mx_records"] = [str(x.exchange) for x in answers]
            result["has_mx"] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.exception.Timeout, dns.resolver.LifetimeTimeout,
                dns.resolver.NoNameservers):
            result["has_mx"] = False
            result["warning"] = "Domain has no MX records"
        except ImportError:
            result["has_mx"] = "dnspython not installed"
        result["valid"] = True
        return result

    def _smtp_verify(self, email, mx_records):
        if not mx_records:
            return None
        mx = mx_records[0]
        try:
            server = smtplib.SMTP(timeout=10)
            server.set_debuglevel(0)
            server.connect(mx)
            server.helo("osint-fox.local")
            server.mail("verify@osint-fox.local")
            code, msg = server.rcpt(email)
            server.quit()
            if code == 250:
                return {"Status": "Mailbox exists", "SMTP Code": str(code), "MX Server": mx}
            elif code == 550:
                return {"Status": "Mailbox does not exist", "SMTP Code": str(code), "MX Server": mx}
            else:
                return {"Status": f"SMTP response: {code}", "MX Server": mx}
        except smtplib.SMTPServerDisconnected:
            return {"Status": "SMTP server disconnected", "MX Server": mx}
        except Exception as e:
            return {"Status": f"SMTP error: {str(e)[:50]}", "MX Server": mx}

    def _social_correlation(self, email):
        local, domain = email.split("@")
        results = {}

        # Check if username part exists on platforms
        results["Username Correlation"] = f"The local part '{local}' may be used as a username elsewhere"

        # Check domain reputation
        results["Domain"] = domain
        results["Mail Provider"] = self._identify_mail_provider(domain)

        # Attempt to correlate with known social patterns
        results["Suggested Searches"] = f"Search for '{local}' on social platforms"

        if results:
            self.results["Social Correlation"] = results

    def _identify_mail_provider(self, domain):
        providers = {
            "gmail.com": "Google Gmail",
            "yahoo.com": "Yahoo Mail",
            "yahoo.co.uk": "Yahoo Mail UK",
            "outlook.com": "Microsoft Outlook",
            "hotmail.com": "Microsoft Hotmail",
            "live.com": "Microsoft Live",
            "aol.com": "AOL Mail",
            "icloud.com": "Apple iCloud",
            "protonmail.com": "ProtonMail",
            "proton.me": "ProtonMail",
            "mail.com": "Mail.com",
            "zoho.com": "Zoho Mail",
            "yandex.com": "Yandex Mail",
            "gmx.com": "GMX Mail",
            "fastmail.com": "FastMail",
            "tutanota.com": "Tutanota",
        }
        return providers.get(domain.lower(), "Custom/Private domain")

    def _web_presence(self, email):
        results = {}
        h = get_gravatar_hash(email)
        results["Gravatar URL"] = f"https://www.gravatar.com/{h}"
        results["Google Search"] = f"https://www.google.com/search?q={email}"
        results["EmailRep"] = f"https://emailrep.io/{email}"
        if self.keys.get("hibp"):
            results["HIBP"] = "https://haveibeenpwned.com/account/" + email
        self.results["Web Presence"] = results
