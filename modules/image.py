import base64
import io
import os
import struct
from datetime import datetime

from modules.base import OSINTModule
from modules.registry import builtin_meta
from utils.network import fetch


@builtin_meta("Image OSINT", "\U0001F5BC", "EXIF data, reverse image search, perceptual hashing")
class ImageModule(OSINTModule):
    def __init__(self):
        super().__init__("Image OSINT", "\U0001F5BC",
                         "EXIF data, reverse image search, perceptual hashing")

    def scan(self, target, progress_callback=None):
        self.results = {}
        self.status = "scanning"

        if target.startswith(("http://", "https://")):
            self.results["Source"] = {"URL": target}
            if progress_callback:
                progress_callback("Downloading image...", 0.1)
            img_data = self._download_image(target)
            if not img_data:
                self.results["Error"] = {"Error": "Could not download image from URL"}
                self.status = "complete"
                return self.results
        elif os.path.isfile(target):
            self.results["Source"] = {"Local Path": target}
            if progress_callback:
                progress_callback("Reading image file...", 0.1)
            with open(target, "rb") as f:
                img_data = f.read()
        else:
            self.results["Error"] = {"Error": "Not a valid URL or file path"}
            self.status = "complete"
            return self.results

        if progress_callback:
            progress_callback("Extracting metadata...", 0.3)
        self._extract_metadata(img_data, target)

        if progress_callback:
            progress_callback("Analyzing EXIF data...", 0.5)
        self._exif_analysis(img_data)

        if progress_callback:
            progress_callback("Generating image hashes...", 0.7)
        self._image_hashes(img_data)

        if progress_callback:
            progress_callback("Generating reverse search URLs...", 0.9)
        self._reverse_search_urls(target)

        if progress_callback:
            progress_callback("Scan complete", 1.0)

        self.status = "complete"
        return self.results

    def _download_image(self, url):
        resp = fetch(url, timeout=15)
        if resp and resp.status_code == 200:
            return resp.content
        return None

    def _extract_metadata(self, img_data, source):
        info = {}
        info["File Size"] = f"{len(img_data):,} bytes"
        info["MD5"] = __import__("hashlib").md5(img_data).hexdigest()
        info["SHA1"] = __import__("hashlib").sha1(img_data).hexdigest()
        info["SHA256"] = __import__("hashlib").sha256(img_data).hexdigest()

        try:
            from PIL import Image
            import io as _io
            img = Image.open(_io.BytesIO(img_data))
            info["Format"] = img.format or "Unknown"
            info["Dimensions"] = f"{img.size[0]}x{img.size[1]}"
            info["Mode"] = img.mode
            info["Width"] = str(img.size[0])
            info["Height"] = str(img.size[1])
            if hasattr(img, "info"):
                dpi = img.info.get("dpi")
                if dpi:
                    info["DPI"] = f"{dpi[0]}x{dpi[1]}"
        except ImportError:
            info["Note"] = "Install Pillow for detailed image metadata"
        except Exception:
            pass

        self.results["Image Metadata"] = info

    def _exif_analysis(self, img_data):
        try:
            from PIL import Image, ExifTags
            import io as _io
            img = Image.open(_io.BytesIO(img_data))
            exif = img.getexif()
            if not exif:
                self.results["EXIF Data"] = {"Status": "No EXIF data found"}
                return

            exif_data = {}
            for tag_id, value in exif.items():
                tag = ExifTags.TAGS.get(tag_id, str(tag_id))
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-8", errors="replace")
                    except Exception:
                        value = str(value)
                exif_data[tag] = str(value)[:200]

            interesting = ["Make", "Model", "Software", "DateTimeOriginal",
                           "GPSInfo", "Artist", "Copyright", "UserComment",
                           "ImageDescription", "Orientation"]
            found = {}
            for key in interesting:
                if key in exif_data:
                    found[key] = exif_data[key]

            if "GPSInfo" in exif_data:
                try:
                    gps = self._parse_gps(exif.get(2))
                    if gps:
                        found["GPS Coordinates"] = gps
                except Exception:
                    pass

            if found:
                self.results["EXIF Data"] = found
            else:
                self.results["EXIF Data"] = {"Note": "EXIF present but no identifying tags",
                                              "Total Tags": str(len(exif_data))}

        except ImportError:
            self.results["EXIF Data"] = {"Note": "Install Pillow for EXIF analysis"}
        except Exception as e:
            self.results["EXIF Data"] = {"Error": str(e)}

    def _parse_gps(self, gps_ifd):
        try:
            from PIL.ExifTags import GPSTAGS
            gps = {}
            for tag_id, value in gps_ifd.items():
                tag = GPSTAGS.get(tag_id, tag_id)
                gps[tag] = value

            def to_decimal(dms, ref):
                try:
                    d, m, s = dms
                    dec = float(d) + float(m) / 60.0 + float(s) / 3600.0
                    if ref in ("S", "W"):
                        dec = -dec
                    return round(dec, 6)
                except Exception:
                    return None

            lat = to_decimal(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef", "N"))
            lon = to_decimal(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef", "E"))
            if lat and lon:
                return f"{lat}, {lon}"
        except Exception:
            pass
        return None

    def _image_hashes(self, img_data):
        hashes = {}
        try:
            from PIL import Image
            import io as _io
            img = Image.open(_io.BytesIO(img_data))

            # Average hash
            small = img.resize((8, 8)).convert("L")
            pixels = list(small.getdata())
            avg = sum(pixels) / len(pixels)
            ahash = "".join("1" if p > avg else "0" for p in pixels)
            hashes["Average Hash (aHash)"] = ahash
            hashes["aHash (hex)"] = hex(int(ahash, 2))[2:].zfill(16)

            # Difference hash
            small = img.resize((9, 8)).convert("L")
            pixels = list(small.getdata())
            dhash = "".join("1" if pixels[i] > pixels[i + 1] else "0"
                            for i in range(0, 64, 1))
            hashes["Difference Hash (dHash)"] = dhash
            hashes["dHash (hex)"] = hex(int(dhash, 2))[2:].zfill(16)

            # Perceptual hash
            from PIL import ImageFilter
            small = img.resize((32, 32)).convert("L")
            from PIL import ImageFilter as IF
            small = small.filter(IF.FIND_EDGES)
            pixels = list(small.getdata())
            avg = sum(pixels) / len(pixels)
            phash = "".join("1" if p > avg else "0" for p in pixels)
            hashes["Perceptual Hash (pHash)"] = phash[:64]
            hashes["pHash (hex)"] = hex(int(phash[:64], 2))[2:].zfill(16)

        except ImportError:
            hashes["Note"] = "Install Pillow for perceptual hashing"
        except Exception:
            pass

        self.results["Image Hashes"] = hashes

    def _reverse_search_urls(self, source):
        urls = {}
        if source.startswith(("http://", "https://")):
            encoded = __import__("urllib").parse.quote(source)
            urls["Google Images"] = f"https://images.google.com/searchbyimage?image_url={encoded}"
            urls["TinEye"] = f"https://www.tineye.com/search?url={encoded}"
            urls["Yandex"] = f"https://yandex.com/images/search?rpt=imagelike&url={encoded}"
            urls["Bing"] = f"https://www.bing.com/images/search?q=imgurl:{encoded}"
            urls["SauceNAO"] = f"https://saucenao.com/search.php?url={encoded}"
            self.results["Reverse Image Search URLs"] = urls
