import re
from modules.base import OSINTModule
from modules.registry import builtin_meta
from modules.username import PLATFORMS
from utils.network import fetch


@builtin_meta("Social Analyzer", "\U0001F465", "Cross-platform profile analysis, consistency, and correlation")
class SocialModule(OSINTModule):
    def __init__(self):
        super().__init__("Social Analyzer", "\U0001F465",
                         "Cross-platform profile analysis, consistency, and correlation")

    def scan(self, username, progress_callback=None):
        self.results = {}
        self.status = "scanning"
        self.results["Target"] = {"Username": username}

        if progress_callback:
            progress_callback("Gathering platform bios...", 0.1)
        bios = self._gather_bios(username, progress_callback)

        if progress_callback:
            progress_callback("Analyzing bio consistency...", 0.5)
        self._analyze_consistency(bios, username)

        if progress_callback:
            progress_callback("Comparing profile metadata...", 0.7)
        self._compare_metadata(bios)

        if progress_callback:
            progress_callback("Generating correlation map...", 0.9)
        self._correlation_analysis(bios, username)

        if progress_callback:
            progress_callback("Scan complete", 1.0)

        self.status = "complete"
        return self.results

    def _gather_bios(self, username, progress_callback=None):
        import concurrent.futures
        bios = []
        profile_platforms = [p for p in PLATFORMS if p.get("category") in
                             ("Social", "Professional", "Blogging", "Development")]
        checked = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            future_map = {}
            for p in profile_platforms[:20]:
                future = ex.submit(self._fetch_bio, username, p)
                future_map[future] = p
            for future in concurrent.futures.as_completed(future_map):
                result = future.result()
                if result:
                    bios.append(result)
                checked += 1
                if progress_callback:
                    progress_callback(f"Analyzing platform {checked}/{len(profile_platforms[:20])}...",
                                      0.1 + 0.4 * (checked / len(profile_platforms[:20])))
        return bios

    def _fetch_bio(self, username, platform):
        try:
            url = platform["url"].format(username)
            resp = fetch(url, timeout=8, allow_redirects=False)
            if resp and resp.status_code == 200:
                text = resp.text[:2000] if hasattr(resp, "text") else ""
                bio_text = self._extract_bio(text)
                return {
                    "platform": platform["name"],
                    "category": platform.get("category", ""),
                    "url": url,
                    "bio_snippet": bio_text[:200] if bio_text else "",
                    "has_profile": True,
                }
        except Exception:
            pass
        return None

    def _extract_bio(self, html):
        if not html:
            return ""
        m = re.search(r'<meta[^>]+name="description"[^>]+content="([^"]+)"', html, re.I)
        if m:
            return m.group(1)
        m = re.search(r'<meta[^>]+property="og:description"[^>]+content="([^"]+)"', html, re.I)
        if m:
            return m.group(1)
        return ""

    def _analyze_consistency(self, bios, username):
        if not bios:
            self.results["Bio Consistency"] = {"Status": "No profiles found to analyze"}
            return

        profiles_found = []
        name_candidates = {}
        for b in bios:
            profiles_found.append(b["platform"])
            snippet = b.get("bio_snippet", "")
            if snippet:
                words = snippet.split()
                for w in words:
                    if w[0].isupper() and len(w) > 2 and w.lower() != username.lower():
                        name_candidates[w] = name_candidates.get(w, 0) + 1

        common_names = [n for n, c in name_candidates.items() if c > 1]
        self.results["Bio Consistency"] = {
            "Profiles Found": ", ".join(profiles_found),
            "Total Platforms": str(len(profiles_found)),
            "Common Name Candidates": ", ".join(common_names[:5]) if common_names else "None detected",
            "Note": "Names appearing across multiple platforms may be the real name",
        }

    def _compare_metadata(self, bios):
        if not bios:
            return
        categories = {}
        for b in bios:
            cat = b.get("category", "Other")
            categories.setdefault(cat, []).append(b["platform"])
        self.results["Category Distribution"] = {
            cat: ", ".join(plats) for cat, plats in categories.items()
        }

    def _correlation_analysis(self, bios, username):
        if not bios:
            return
        self.results["Correlation"] = {
            "Username": username,
            "Unique Platforms": str(len(bios)),
            "Primary Categories": ", ".join(
                sorted(set(b.get("category", "") for b in bios if b.get("category")))
            ),
            "Note": "Username is active across multiple platform categories",
        }
