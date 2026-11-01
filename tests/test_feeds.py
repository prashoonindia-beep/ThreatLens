from types import SimpleNamespace
from app.routes import _feed_records

def test_cisa_kev_feed_parser():
    response = SimpleNamespace(json=lambda: {
        "vulnerabilities": [{"cveID": "CVE-2024-12345"}]
    })
    assert _feed_records("cisa_kev", response) == [
        ("CVE-2024-12345", "cve", 95, "known-exploited")
    ]

def test_urlhaus_feed_parser():
    response = SimpleNamespace(text="# comment\nid,dateadded,url\n1,2026-01-01,https://bad.example/a\n")
    assert _feed_records("urlhaus", response) == [
        ("https://bad.example/a", "url", 80, "malware-distribution")
    ]
