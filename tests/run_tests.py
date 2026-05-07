import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.base import OSINTModule


def test_base_module():
    m = OSINTModule("Test", "T", "Test module")
    assert m.name == "Test"
    assert m.icon == "T"
    assert m.description == "Test module"
    assert m.status == "idle"
    assert m.get_results() == {}
    summary = m.get_summary()
    assert "total" in summary
    assert "found" in summary
    flat = m.get_results_flat()
    assert len(flat) >= 3
    print("[PASS] base module")


def test_username_module():
    from modules.username import UsernameModule
    m = UsernameModule()
    assert m.name == "Username OSINT"
    results = m.scan("testuser", lambda msg, pct: None)
    assert "Summary" in results
    assert results["Summary"]["Platforms Checked"] > 35
    print(f"[PASS] username module ({results['Summary']['Platforms Checked']} platforms)")


def test_email_module():
    from modules.email import EmailModule
    m = EmailModule()
    results = m.scan("user@example.com", lambda msg, pct: None)
    assert "Validation" in results
    assert results["Validation"].get("format") == "Valid"
    print("[PASS] email module")


def test_phone_module():
    from modules.phone import PhoneModule
    m = PhoneModule()
    results = m.scan("+14155551234", lambda msg, pct: None)
    assert "Parsing" in results
    assert results["Parsing"].get("valid") == True
    print("[PASS] phone module")


def test_domain_module():
    from modules.domain import DomainModule
    m = DomainModule()
    results = m.scan("google.com", lambda msg, pct: None)
    assert "DNS Records" in results or "Target" in results
    print(f"[PASS] domain module (keys: {list(results.keys())[:4]})")


def test_social_module():
    from modules.social import SocialModule
    m = SocialModule()
    results = m.scan("testuser", lambda msg, pct: None)
    assert "Target" in results
    print(f"[PASS] social module (keys: {list(results.keys())[:3]})")


def test_image_module():
    from modules.image import ImageModule
    m = ImageModule()
    results = m.scan("https://example.com/nonexistent.jpg", lambda msg, pct: None)
    assert "Error" in results or "Source" in results
    print(f"[PASS] image module (error handling)")


def test_breaches_module():
    from modules.breaches import BreachModule
    m = BreachModule()
    results = m.scan("test@example.com", lambda msg, pct: None)
    assert "Target" in results
    assert "Have I Been Pwned" in results
    print("[PASS] breaches module")


def test_geo_module():
    from modules.geo import GeoModule
    m = GeoModule()
    results = m.scan("8.8.8.8", lambda msg, pct: None)
    assert "Geolocation" in results or "Target Resolution" in results
    print(f"[PASS] geo module")


def test_exporter():
    from utils.exporter import export_to_txt, export_to_json, export_to_csv, export_to_html
    from modules.username import UsernameModule
    import tempfile
    m = UsernameModule()
    m.scan("testuser", lambda msg, pct: None)
    flat = m.get_results_flat()
    tmp = tempfile.gettempdir()
    for fmt, func, ext in [
        ("txt", export_to_txt, ".txt"),
        ("json", export_to_json, ".json"),
        ("csv", export_to_csv, ".csv"),
        ("html", export_to_html, ".html"),
    ]:
        fp = os.path.join(tmp, f"test_osint_{fmt}{ext}")
        func(flat, fp, "testuser")
        assert os.path.getsize(fp) > 50
        os.remove(fp)
    print("[PASS] all export formats")


def test_cache():
    from utils.cache import ScanCache
    import tempfile
    c = ScanCache(tempfile.mkdtemp())
    c.set("test_key", {"value": 42})
    result = c.get("test_key", max_age=3600)
    assert result == {"value": 42}
    assert c.get("nonexistent") is None
    c.clear()
    print("[PASS] cache")


def test_apikeys():
    from utils.apikeys import APIKeyManager
    import tempfile
    path = os.path.join(tempfile.mkdtemp(), "keys.json")
    km = APIKeyManager(path)
    km.set("test_service", "test_key_value")
    assert km.get("test_service") == "test_key_value"
    km.delete("test_service")
    assert km.get("test_service") == ""
    print("[PASS] API key manager")


def test_registry():
    from modules.registry import discover_modules, get_module
    discover_modules()
    m = get_module("Username OSINT")
    assert m is not None
    print("[PASS] module registry")


if __name__ == "__main__":
    tests = [
        test_base_module,
        test_cache,
        test_apikeys,
        test_registry,
        test_exporter,
        test_username_module,
        test_email_module,
        test_phone_module,
        test_domain_module,
        test_social_module,
        test_image_module,
        test_breaches_module,
        test_geo_module,
    ]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"[FAIL] {t.__name__}: {e}")
            failed += 1
    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed, {len(tests)} total")
    sys.exit(1 if failed > 0 else 0)
