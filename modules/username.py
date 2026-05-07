import concurrent.futures
from modules.base import OSINTModule
from modules.registry import builtin_meta
from utils.network import fetch, rate_limit
from utils.cache import ScanCache

cache = ScanCache()

PLATFORMS = [
    {"name": "GitHub", "url": "https://api.github.com/users/{}", "check": "json",
     "fields": {"login": "Username", "name": "Full Name", "bio": "Bio",
                "location": "Location", "email": "Email", "blog": "Website",
                "company": "Company", "public_repos": "Public Repos",
                "followers": "Followers", "following": "Following",
                "created_at": "Joined", "html_url": "Profile URL"},
     "category": "Development", "rate_limit_domain": "api.github.com"},
    {"name": "GitLab", "url": "https://gitlab.com/api/v4/users?username={}", "check": "json_array",
     "fields": {"id": "ID", "name": "Full Name", "web_url": "Profile URL",
                "state": "State", "public_repos": "Public Projects"},
     "category": "Development", "rate_limit_domain": "gitlab.com"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}/about.json", "check": "json_path",
     "json_path": ["data"],
     "fields": {"subreddit": "Subreddit", "total_karma": "Total Karma",
                "link_karma": "Link Karma", "comment_karma": "Comment Karma",
                "created_utc": "Account Age (Unix)", "is_employee": "Employee",
                "has_verified_email": "Verified Email"},
     "category": "Social", "rate_limit_domain": "reddit.com"},
    {"name": "Telegram", "url": "https://t.me/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Messaging"},
    {"name": "YouTube", "url": "https://www.youtube.com/@{}", "check": "status",
     "fields": {"channel_url": "Channel URL"}, "category": "Social"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Social"},
    {"name": "Medium", "url": "https://medium.com/@{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Blogging"},
    {"name": "Dev.to", "url": "https://dev.to/api/users/by_username?url={}", "check": "json",
     "fields": {"username": "Username", "name": "Full Name", "bio": "Bio",
                "location": "Location", "website_url": "Website",
                "twitter_username": "Twitter", "github_username": "GitHub",
                "joined_at": "Joined"},
     "category": "Development", "rate_limit_domain": "dev.to"},
    {"name": "Keybase", "url": "https://keybase.io/_/api/1.0/user/lookup.json?username={}",
     "check": "json_path", "json_path": ["them", 0],
     "fields": {"username": "Username", "bio": "Bio", "full_name": "Full Name",
                "location": "Location"},
     "category": "Security", "rate_limit_domain": "keybase.io"},
    {"name": "HackerNews", "url": "https://hacker-news.firebaseio.com/v0/user/{}.json",
     "check": "json",
     "fields": {"id": "Username", "karma": "Karma", "created": "Created (Unix)", "about": "About"},
     "category": "Social"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{}/", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Social"},
    {"name": "Replit", "url": "https://replit.com/@{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Development"},
    {"name": "Pastebin", "url": "https://pastebin.com/u/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Development"},
    {"name": "BitBucket", "url": "https://api.bitbucket.org/2.0/users/{}", "check": "json",
     "fields": {"display_name": "Display Name", "nickname": "Nickname",
                "website": "Website", "location": "Location", "created_on": "Joined"},
     "category": "Development", "rate_limit_domain": "bitbucket.org"},
    {"name": "Twitch", "url": "https://twitch.tv/{}", "check": "status",
     "fields": {"channel_url": "Channel URL"}, "category": "Social"},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{}/", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Gaming"},
    {"name": "Flickr", "url": "https://www.flickr.com/people/{}/", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Social"},
    {"name": "VK", "url": "https://vk.com/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Social"},
    {"name": "Dailymotion", "url": "https://api.dailymotion.com/user/{}", "check": "json",
     "fields": {"screenname": "Screen Name", "country": "Country",
                "language": "Language", "total_views": "Total Views"},
     "category": "Social", "rate_limit_domain": "dailymotion.com"},
    {"name": "AskFM", "url": "https://ask.fm/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Social"},
    {"name": "Imgur", "url": "https://imgur.com/user/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Social"},
    {"name": "SlideShare", "url": "https://www.slideshare.net/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Professional"},
    {"name": "Scribd", "url": "https://www.scribd.com/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Professional"},
    {"name": "Behance", "url": "https://www.behance.net/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Professional"},
    {"name": "Dribbble", "url": "https://dribbble.com/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Professional"},
    {"name": "Codecademy", "url": "https://www.codecademy.com/profiles/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Development"},
    {"name": "GeeksforGeeks", "url": "https://auth.geeksforgeeks.org/user/{}/", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Development"},
    {"name": "Strava", "url": "https://www.strava.com/athletes/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Fitness"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Music"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Music"},
    {"name": "Internet Archive", "url": "https://archive.org/details/@{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Archives"},
    {"name": "Disqus", "url": "https://disqus.com/by/{}/", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Social"},
    {"name": "About.me", "url": "https://about.me/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Professional"},
    {"name": "Venmo", "url": "https://venmo.com/u/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Finance"},
    {"name": "Mastodon (mastodon.social)", "url": "https://mastodon.social/@{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Social"},
    {"name": "Buy Me a Coffee", "url": "https://buymeacoffee.com/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Professional"},
    {"name": "Gravatar", "url": "https://en.gravatar.com/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Web"},
    {"name": "Snapchat", "url": "https://www.snapchat.com/add/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Social"},
    {"name": "Patreon", "url": "https://www.patreon.com/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Professional"},
    {"name": "Linktree", "url": "https://linktr.ee/{}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Web"},
    {"name": "Cash App", "url": "https://cash.app/${}", "check": "status",
     "fields": {"profile_url": "Profile URL"}, "category": "Finance"},
]


@builtin_meta("Username OSINT", "\U0001F575", "Search 40+ platforms for username presence")
class UsernameModule(OSINTModule):
    def __init__(self):
        super().__init__("Username OSINT", "\U0001F575",
                         "Search 40+ platforms for username presence")

    def scan(self, username, progress_callback=None):
        self.results = {}
        self.status = "scanning"
        found = []
        not_found = []
        error = []
        categories = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
            future_map = {}
            for platform in PLATFORMS:
                future = executor.submit(self._check_platform, username, platform)
                future_map[future] = platform

            completed = 0
            total = len(PLATFORMS)
            for future in concurrent.futures.as_completed(future_map):
                platform = future_map[future]
                completed += 1
                if progress_callback:
                    progress_callback(f"Checking {platform['name']}...", completed / total)

                try:
                    result = future.result()
                    if result["found"]:
                        found.append(result)
                        cat = platform["category"]
                        if cat not in categories:
                            categories[cat] = []
                        categories[cat].append(result)
                    else:
                        if result.get("error"):
                            error.append(result)
                        else:
                            not_found.append(result)
                except Exception:
                    error.append({"platform": platform["name"], "found": False, "error": True})

        self.results["Summary"] = {
            "Platforms Checked": len(PLATFORMS),
            "Profiles Found": len(found),
            "Not Found": len(not_found),
            "Errors": len(error),
        }
        if found:
            for cat, items in sorted(categories.items()):
                self.results[f"Found - {cat}"] = items
        self.status = "complete"
        return self.results

    def _check_platform(self, username, platform):
        url = platform["url"].format(username)
        result = {"platform": platform["name"], "url": url, "found": False,
                  "error": False, "category": platform["category"], "data": {}}

        # Check cache first
        cache_key = f"username_{platform['name']}_{username}"
        cached = cache.get(cache_key, max_age=3600)
        if cached is not None:
            result.update(cached)
            return result

        # Rate limit per platform domain
        rl_domain = platform.get("rate_limit_domain", platform["name"].lower())
        rate_limit(rl_domain, 1.0)

        try:
            check_type = platform["check"]
            if check_type == "status":
                resp = fetch(url, allow_redirects=False)
                if resp is None:
                    result["error"] = True
                    return result
                result["found"] = resp.status_code == 200
            elif check_type == "json":
                data = fetch(url, json_response=True)
                if data is None:
                    result["error"] = True
                    return result
                if data and not isinstance(data, list):
                    result["found"] = True
                    for key, label in platform.get("fields", {}).items():
                        val = data.get(key)
                        if val:
                            result["data"][label] = val
                elif isinstance(data, list) and len(data) > 0:
                    result["found"] = True
                    for key, label in platform.get("fields", {}).items():
                        val = data[0].get(key)
                        if val:
                            result["data"][label] = val
            elif check_type == "json_array":
                data = fetch(url, json_response=True)
                if data is None:
                    result["error"] = True
                    return result
                if isinstance(data, list) and len(data) > 0:
                    result["found"] = True
                    for key, label in platform.get("fields", {}).items():
                        val = data[0].get(key)
                        if val:
                            result["data"][label] = val
            elif check_type == "json_path":
                data = fetch(url, json_response=True)
                if data is None:
                    result["error"] = True
                    return result
                current = data
                for path_key in platform.get("json_path", []):
                    if isinstance(current, dict) and path_key in current:
                        current = current[path_key]
                    elif isinstance(current, list) and isinstance(path_key, int) and path_key < len(current):
                        current = current[path_key]
                    else:
                        current = None
                        break
                if current and isinstance(current, dict):
                    result["found"] = True
                    for key, label in platform.get("fields", {}).items():
                        val = current.get(key)
                        if val:
                            result["data"][label] = val
        except Exception:
            result["error"] = True

        cache.set(cache_key, result)
        return result
