import json

from zscan import intel
from zscan.cli import main
from zscan.scanner import Scanner
from zscan.yara_engine import YaraEngine

from samples import EICAR

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def test_hashlist_hit(tmp_path, capsys):
    hl = tmp_path / "bad.txt"
    target = tmp_path / "x.bin"
    target.write_bytes(b"totally normal bytes")
    import hashlib
    hl.write_text(f"# comment\n{hashlib.sha256(target.read_bytes()).hexdigest().upper()},TestFamily\n")
    code = main([str(target), "--hashlist", str(hl), "--no-color", "--no-community"])
    out = capsys.readouterr().out
    assert code == 2
    assert "Hash on known-malware list" in out and "TestFamily" in out


class FakeHTTP:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, url, data=None, headers=None, timeout=15):
        self.calls.append((url, data, headers))
        for prefix, resp in self.routes.items():
            if url.startswith(prefix):
                return resp
        return 404, b""


def test_online_sources(monkeypatch):
    monkeypatch.setenv("MALWAREBAZAAR_API_KEY", "k1")
    monkeypatch.setenv("VT_API_KEY", "k2")
    monkeypatch.setenv("VT_MIN_INTERVAL", "0")
    http = FakeHTTP({
        "https://mb-api.abuse.ch/": (200, json.dumps({"query_status": "ok", "data": [
            {"signature": "TestFamily", "tags": ["exe", "test"]}]}).encode()),
        "https://www.virustotal.com/": (200, json.dumps({"data": {"attributes": {
            "last_analysis_stats": {"malicious": 60, "undetected": 10},
            "popular_threat_classification": {"suggested_threat_label": "eicar/test"}}}}).encode()),
    })
    oi = intel.OnlineIntel(http=http)
    titles = {f.title: f for f in oi.lookup(EICAR_SHA256, worth_vt=True)}
    assert titles["Known malware on MalwareBazaar"].severity == 5
    assert "TestFamily" in titles["Known malware on MalwareBazaar"].detail
    assert titles["Flagged by VirusTotal engines"].detail == "60/70 eicar/test"
    # Only the hash is sent: no request body carries file content
    assert all(EICAR not in (d or b"") for _, d, _ in http.calls)
    # Second lookup is served from cache
    n = len(http.calls)
    oi.lookup(EICAR_SHA256, worth_vt=True)
    assert len(http.calls) == n


def test_online_cache_persists():
    http = FakeHTTP({"https://hashlookup.circl.lu/": (200, b'{"FileName": "ls"}')})
    oi = intel.OnlineIntel(http=http)
    assert oi.lookup("a" * 64, worth_vt=False)[0].title == "Known-good file (CIRCL hashlookup)"
    oi.save_cache()
    http2 = FakeHTTP({})
    assert intel.OnlineIntel(http=http2).lookup("a" * 64, worth_vt=False)[0].severity == 1
    assert http2.calls == []


def test_network_failure_is_a_warning_not_a_crash():
    def broken(*a, **k):
        raise OSError("network unreachable")
    oi = intel.OnlineIntel(http=broken)
    assert oi.lookup("b" * 64, worth_vt=True) == []
    assert oi.warnings and "network unreachable" in oi.warnings[0]


def test_vt_skipped_for_plain_clean_text(monkeypatch, tmp_path):
    monkeypatch.setenv("VT_API_KEY", "k")
    http = FakeHTTP({})
    s = Scanner(YaraEngine(community=False), online=intel.OnlineIntel(http=http))
    p = tmp_path / "notes.txt"
    p.write_text("hello")
    s.scan_file(p)
    assert not any("virustotal" in u for u, _, _ in http.calls)


def test_bazaar_list_update():
    body = b"# header\n" + EICAR_SHA256.encode() + b"\nnot-a-hash\n"
    path, n = intel.update_bazaar_list(http=lambda url, timeout=60: (200, body))
    assert n == 1
    hl = intel.HashList(intel.default_hash_lists())
    assert hl.lookup({"sha256": EICAR_SHA256})[0].severity == 5
