import json
import os
import time

CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".cache")


class ScanCache:
    def __init__(self, cache_dir=None):
        self.cache_dir = cache_dir or CACHE_DIR
        os.makedirs(self.cache_dir, exist_ok=True)

    def _path(self, key):
        safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in key)
        return os.path.join(self.cache_dir, f"{safe}.json")

    def get(self, key, max_age=3600):
        path = self._path(key)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r") as f:
                data = json.load(f)
            if time.time() - data.get("ts", 0) > max_age:
                return None
            return data.get("result")
        except Exception:
            return None

    def set(self, key, result):
        path = self._path(key)
        with open(path, "w") as f:
            json.dump({"ts": time.time(), "result": result}, f)

    def clear(self, max_age=None):
        now = time.time()
        for fname in os.listdir(self.cache_dir):
            if fname.endswith(".json"):
                path = os.path.join(self.cache_dir, fname)
                if max_age:
                    try:
                        with open(path, "r") as f:
                            data = json.load(f)
                        if now - data.get("ts", 0) > max_age:
                            os.remove(path)
                    except Exception:
                        os.remove(path)
                else:
                    os.remove(path)
