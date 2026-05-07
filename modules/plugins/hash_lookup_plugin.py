from modules.base import OSINTModule
from modules.registry import builtin_meta


@builtin_meta("Hash Lookup", "#", "Lookup file hashes in public databases")
class HashLookupPlugin(OSINTModule):
    def __init__(self):
        super().__init__("Hash Lookup", "#",
                         "Lookup file hashes (MD5/SHA1/SHA256/SHA512) in public databases")

    def scan(self, target, progress_callback=None):
        self.results = {}
        self.status = "scanning"
        h = target.strip()
        if progress_callback:
            progress_callback("Checking hash databases...", 0.3)
        self.results["Hash"] = {"Hash": h, "Type": self._identify_hash(h)}
        if progress_callback:
            progress_callback("Generating lookup URLs...", 0.7)
        self.results["Lookup URLs"] = {
            "VirusTotal": f"https://www.virustotal.com/gui/search/{h}",
            "Hybrid Analysis": f"https://www.hybrid-analysis.com/search?query={h}",
            "Metadefender": f"https://metadefender.opswat.com/results/file/{h}",
        }
        if progress_callback:
            progress_callback("Plugin scan complete", 1.0)
        self.status = "complete"
        return self.results

    def _identify_hash(self, h):
        l = len(h)
        if l == 32:
            return "MD5"
        elif l == 40:
            return "SHA1"
        elif l == 64:
            return "SHA256"
        elif l == 128:
            return "SHA512"
        return "Unknown"
