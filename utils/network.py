import requests
import hashlib
import time
from urllib.parse import urlparse

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Accept": "text/html,application/json,*/*",
    "Accept-Language": "en-US,en;q=0.5",
})

_proxy = None
last_request_time = {}


def set_proxy(proxy_url):
    global _proxy
    _proxy = proxy_url
    session.proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else {}
    session.verify = not (proxy_url and "tor" in proxy_url.lower())


def clear_proxy():
    global _proxy
    _proxy = None
    session.proxies = {}
    session.verify = True


def get_proxy():
    return _proxy


def rate_limit(domain, min_interval=1.5):
    now = time.time()
    key = f"rate_{domain}"
    if key in last_request_time:
        elapsed = now - last_request_time[key]
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
    last_request_time[key] = time.time()


def fetch(url, headers=None, timeout=20, json_response=False, allow_redirects=True):
    try:
        merged = headers if headers else {}
        resp = session.get(url, headers=merged, timeout=timeout,
                           allow_redirects=allow_redirects)
        if json_response:
            return resp.json() if resp.status_code == 200 else None
        return resp
    except (requests.ConnectionError, requests.Timeout,
            requests.exceptions.RequestException):
        return None


def fetch_post(url, data=None, json_data=None, headers=None, timeout=20):
    try:
        merged = headers if headers else {}
        resp = session.post(url, data=data, json=json_data,
                            headers=merged, timeout=timeout)
        return resp
    except (requests.ConnectionError, requests.Timeout,
            requests.exceptions.RequestException):
        return None


def check_url_exists(url, headers=None):
    resp = fetch(url, headers=headers, allow_redirects=False)
    if resp is None:
        return None
    return resp.status_code == 200


def get_gravatar_hash(email):
    return hashlib.md5(email.lower().strip().encode()).hexdigest()


def check_gravatar(email):
    h = get_gravatar_hash(email)
    url = f"https://www.gravatar.com/{h}.json"
    resp = fetch(url, json_response=True)
    if resp:
        entries = resp.get("entry", [])
        if entries:
            profile = entries[0]
            return {
                "exists": True,
                "avatar_url": f"https://www.gravatar.com/avatar/{h}?s=400",
                "display_name": profile.get("displayName", ""),
                "about": profile.get("aboutMe", ""),
                "location": profile.get("currentLocation", ""),
                "urls": profile.get("urls", []),
                "accounts": profile.get("accounts", []),
            }
    return {"exists": False}


def check_emailrep(email, api_key=""):
    rate_limit("emailrep.io", 2.0)
    url = "https://emailrep.io/" + email
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Key"] = api_key
    resp = fetch(url, headers=headers, json_response=True)
    if resp is None:
        return None
    return resp


def check_hibp(email, api_key=""):
    h = hashlib.sha1(email.lower().encode()).hexdigest().upper()
    prefix = h[:5]
    suffix = h[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {}
    if api_key:
        headers["hibp-api-key"] = api_key
    resp = fetch(url, headers=headers, timeout=10)
    if resp and resp.status_code == 200:
        for line in resp.text.splitlines():
            if line.startswith(suffix):
                count = int(line.split(":")[1].strip())
                return count
    return None
