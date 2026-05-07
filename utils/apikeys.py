import json
import os

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".apikeys.json")


class APIKeyManager:
    def __init__(self, config_path=None):
        self.config_path = config_path or CONFIG_PATH
        self.keys = {}
        self._load()

    def _load(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    self.keys = json.load(f)
            except Exception:
                self.keys = {}

    def _save(self):
        with open(self.config_path, "w") as f:
            json.dump(self.keys, f, indent=2)

    def get(self, service):
        return self.keys.get(service, "")

    def set(self, service, key):
        self.keys[service] = key
        self._save()

    def delete(self, service):
        self.keys.pop(service, None)
        self._save()

    def all(self):
        return dict(self.keys)

    SERVICES = {
        "shodan": "Shodan (shodan.io)",
        "censys": "Censys (censys.io)",
        "hibp": "Have I Been Pwned",
        "dehashed": "DeHashed (dehashed.com)",
        "intelx": "IntelX (intelx.io)",
        "emailrep": "EmailRep (emailrep.io)",
        "numverify": "NumVerify (numverify.com)",
        "twilio_sid": "Twilio Account SID",
        "twilio_token": "Twilio Auth Token",
        "virustotal": "VirusTotal (virustotal.com)",
    }
