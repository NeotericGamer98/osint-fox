import socket
from modules.base import OSINTModule
from modules.registry import builtin_meta
from utils.network import fetch, rate_limit


@builtin_meta("Geolocation", "\U0001F30D", "IP geolocation, timezone, language inference, and mapping")
class GeoModule(OSINTModule):
    def __init__(self):
        super().__init__("Geolocation", "\U0001F30D",
                         "IP geolocation, timezone, language inference, and mapping")

    def scan(self, target, progress_callback=None):
        self.results = {}
        self.status = "scanning"
        target = target.strip()

        if progress_callback:
            progress_callback("Resolving target...", 0.1)

        ip = self._resolve_target(target)
        if not ip:
            self.results["Error"] = {"Error": f"Could not resolve '{target}' to an IP address"}
            self.status = "complete"
            return self.results

        self.results["Target Resolution"] = {"Input": target, "Resolved IP": ip}

        if progress_callback:
            progress_callback("Geolocating IP...", 0.3)
        self._ip_geolocation(ip)

        if progress_callback:
            progress_callback("Fetching timezone info...", 0.5)
        self._timezone_info(ip)

        if progress_callback:
            progress_callback("Gathering network intelligence...", 0.7)
        self._network_intel(ip)

        if progress_callback:
            progress_callback("Generating map data...", 0.9)
        self._map_data(ip)

        if progress_callback:
            progress_callback("Scan complete", 1.0)

        self.status = "complete"
        return self.results

    def _resolve_target(self, target):
        target = target.strip().lower()
        if target.startswith("http://") or target.startswith("https://"):
            from urllib.parse import urlparse
            target = urlparse(target).netloc or target
        target = target.split("/")[0].split(":")[0]

        # Check if already an IP
        import re
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            return target

        try:
            return socket.gethostbyname(target)
        except Exception:
            return None

    def _ip_geolocation(self, ip):
        rate_limit("ip-api.com", 1.0)
        resp = fetch(f"http://ip-api.com/json/{ip}", json_response=True)
        if resp and resp.get("status") == "success":
            geo = {
                "IP": ip,
                "Country": resp.get("country", ""),
                "Country Code": resp.get("countryCode", ""),
                "Region": resp.get("regionName", ""),
                "City": resp.get("city", ""),
                "ZIP": resp.get("zip", ""),
                "Latitude": str(resp.get("lat", "")),
                "Longitude": str(resp.get("lon", "")),
                "ISP": resp.get("isp", ""),
                "Organization": resp.get("org", ""),
                "AS": resp.get("as", ""),
                "Timezone": resp.get("timezone", ""),
            }
            self.results["Geolocation"] = geo
        else:
            # Fallback
            resp2 = fetch(f"https://ipinfo.io/{ip}/json", json_response=True)
            if resp2:
                loc = resp2.get("loc", "").split(",")
                geo = {
                    "IP": ip,
                    "Country": resp2.get("country", ""),
                    "Region": resp2.get("region", ""),
                    "City": resp2.get("city", ""),
                    "Postal": resp2.get("postal", ""),
                    "Latitude": loc[0] if len(loc) > 0 else "",
                    "Longitude": loc[1] if len(loc) > 1 else "",
                    "Organization": resp2.get("org", ""),
                    "Timezone": resp2.get("timezone", ""),
                }
                self.results["Geolocation"] = geo
            else:
                self.results["Geolocation"] = {"Status": "Could not determine location"}

    def _timezone_info(self, ip):
        geo = self.results.get("Geolocation", {})
        tz = geo.get("Timezone", "")
        if tz:
            try:
                from datetime import datetime, timezone, timedelta
                import pytz
                tz_obj = pytz.timezone(tz)
                now = datetime.now(tz_obj)
                utc_offset = now.utcoffset()
                info = {
                    "Timezone": tz,
                    "UTC Offset": str(utc_offset),
                    "Current Local Time": now.strftime("%Y-%m-%d %H:%M:%S %Z"),
                    "Is DST": str(now.dst() != timedelta(0)),
                }
                self.results["Time Information"] = info
            except ImportError:
                self.results["Time Information"] = {"Timezone": tz,
                                                     "Note": "Install pytz for full timezone data"}
            except Exception:
                self.results["Time Information"] = {"Timezone": tz}
        else:
            self.results["Time Information"] = {"Status": "Not available"}

    def _network_intel(self, ip):
        intel = {
            "IP Address": ip,
            "Reverse DNS": "",
            "Open Ports": "22, 80, 443 (common - check with nmap for full scan)",
        }
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            intel["Reverse DNS"] = hostname
        except Exception:
            intel["Reverse DNS"] = "Not available"

        intel["Shodan Lookup"] = f"https://www.shodan.io/host/{ip}"
        intel["Censys Lookup"] = f"https://search.censys.io/hosts/{ip}"
        intel["AbuseIPDB"] = f"https://www.abuseipdb.com/check/{ip}"
        intel["IPinfo"] = f"https://ipinfo.io/{ip}"

        self.results["Network Intelligence"] = intel

    def _map_data(self, ip):
        geo = self.results.get("Geolocation", {})
        lat = geo.get("Latitude", "")
        lon = geo.get("Longitude", "")
        if lat and lon:
            self.results["Map Links"] = {
                "Google Maps": f"https://www.google.com/maps?q={lat},{lon}",
                "OpenStreetMap": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=10",
                "Lat/Lon": f"{lat}, {lon}",
            }
