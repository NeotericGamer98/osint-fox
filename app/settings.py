import json
import os

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".settings.json")


class AppSettings:
    def __init__(self):
        self.path = CONFIG_PATH
        self.data = self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save(self):
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2)

    def get(self, key, default=None):
        val = self.data.get(key, default)
        return val

    def set(self, key, value):
        self.data[key] = value
        self._save()

    def get_all(self):
        return dict(self.data)
