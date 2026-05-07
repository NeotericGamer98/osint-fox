import json
import os
from datetime import datetime


SESSION_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sessions")


class SessionManager:
    def __init__(self, session_dir=None):
        self.session_dir = session_dir or SESSION_DIR
        os.makedirs(self.session_dir, exist_ok=True)

    def save(self, target, module_name, results_flat, filepath=None):
        if not filepath:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe = "".join(c if c.isalnum() else "_" for c in target[:20])
            filepath = os.path.join(self.session_dir, f"{safe}_{ts}.osint")
        data = {
            "version": "1.1",
            "target": target,
            "module": module_name,
            "timestamp": datetime.now().isoformat(),
            "results": results_flat,
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return filepath

    def load(self, filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data

    def list_sessions(self):
        sessions = []
        if os.path.isdir(self.session_dir):
            for fname in os.listdir(self.session_dir):
                if fname.endswith(".osint"):
                    path = os.path.join(self.session_dir, fname)
                    try:
                        with open(path, "r") as f:
                            data = json.load(f)
                        sessions.append({
                            "path": path,
                            "filename": fname,
                            "target": data.get("target", "Unknown"),
                            "module": data.get("module", "Unknown"),
                            "timestamp": data.get("timestamp", ""),
                        })
                    except Exception:
                        pass
        return sorted(sessions, key=lambda s: s.get("timestamp", ""), reverse=True)
