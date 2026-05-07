import requests
import hashlib
import json
import time

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Accept": "text/html,application/json,*/*",
    "Accept-Language": "en-US,en;q=0.5"
})

last_request_time = {}

def rate_limit(domain, min_interval=1.0):
    now = time.time()
    key = f"rate_{domain}"
    if key in last_request_time:
        elapsed = now - last_request_time[key]
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
    last_request_time[key] = time.time()

def fetch(url, headers=None, timeout=15, json_response=False, allow_redirects=True):
    try:
        merged_headers = headers if headers else {}
        resp = session.get(
            url,
            headers=merged_headers,
            timeout=timeout,
            allow_redirects=allow_redirects
        )
        if json_response:
            return resp.json() if resp.status_code == 200 else None
        return resp
    except (requests.ConnectionError, requests.Timeout, requests.exceptions.RequestException):
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
                "accounts": profile.get("accounts", [])
            }
    return {"exists": False}

def check_emailrep(email):
    rate_limit("emailrep.io", 2.0)
    url = "https://emailrep.io/" + email
    headers = {"Accept": "application/json"}
    resp = fetch(url, headers=headers, json_response=True)
    if resp is None:
        return None
    return resp

def check_hibp(email):
    h = hashlib.sha1(email.lower().encode()).hexdigest().upper()
    prefix = h[:5]
    suffix = h[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    resp = fetch(url, timeout=10)
    if resp and resp.status_code == 200:
        for line in resp.text.splitlines():
            if line.startswith(suffix):
                count = int(line.split(":")[1].strip())
                return count
    return None
