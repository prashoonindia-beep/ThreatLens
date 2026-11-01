import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database import Base, get_db

@pytest.fixture()
def client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()

def test_health_and_feed_catalog(client):
    assert client.get("/health").status_code == 200
    feeds = client.get("/feeds").json()
    assert {x["key"] for x in feeds} == {
        "feodo", "urlhaus", "malwarebazaar", "threatfox", "cisa_kev", "otx"
    }

def test_ioc_event_correlation_alert_lifecycle_and_incident(client):
    payload = {
        "indicator": "198.51.100.25",
        "indicator_type": "ip",
        "severity": "high",
        "confidence": 90,
        "source": "test",
        "tlp": "clear",
        "status": "active",
        "tags": '["test"]',
        "attack_techniques": '["T1059"]',
        "analyst_notes": "Integration test IOC"
    }
    created = client.post("/iocs/", json=payload)
    assert created.status_code == 201
    event = client.post("/events", json={
        "indicator": "198.51.100.25",
        "event_type": "connection_observed",
        "source": "test_sensor"
    })
    assert event.status_code == 200
    assert event.json()["matched_indicators"] == 1
    alerts = client.get("/alerts").json()
    assert alerts
    updated = client.patch(f"/alerts/{alerts[0]['id']}", json={
        "status": "acknowledged", "assignee": "analyst"
    })
    assert updated.status_code == 200
    assert updated.json()["status"] == "acknowledged"

    incident = client.post("/incidents", json={
        "title": "Suspicious outbound connection",
        "severity": "high",
        "owner": "analyst"
    })
    assert incident.status_code == 200
    incident_id = incident.json()["id"]
    note = client.post(f"/incidents/{incident_id}/timeline", json={
        "description": "Reviewed the correlated event",
        "actor": "analyst"
    })
    assert note.status_code == 200
    timeline = client.get(f"/incidents/{incident_id}/timeline")
    assert timeline.status_code == 200
    assert len(timeline.json()) == 2

def test_csv_and_pdf_exports(client):
    csv_response = client.get("/export/csv")
    assert csv_response.status_code == 200
    assert "text/csv" in csv_response.headers["content-type"]
    pdf_response = client.get("/reports/summary.pdf")
    assert pdf_response.status_code == 200
    assert pdf_response.content.startswith(b"%PDF")


def test_tlp_filtered_stix_export(client):
    base = {
        "indicator_type": "domain", "severity": "medium", "confidence": 70,
        "source": "test", "status": "active", "tags": "[]",
        "attack_techniques": "[]"
    }
    client.post("/iocs/", json={**base, "indicator": "public.example", "tlp": "clear"})
    client.post("/iocs/", json={**base, "indicator": "restricted.example", "tlp": "red"})
    exported = client.get("/export/stix?max_tlp=amber").json()
    names = [obj["name"] for obj in exported["objects"]]
    assert "public.example" in names
    assert "restricted.example" not in names

def test_indicator_source_provenance(client):
    created = client.post("/iocs/", json={
        "indicator": "203.0.113.45", "indicator_type": "ip",
        "severity": "medium", "confidence": 60, "source": "manual",
        "tlp": "clear", "status": "active", "tags": "[]",
        "attack_techniques": "[]"
    }).json()
    sources = client.get(f"/iocs/{created['id']}/sources")
    assert sources.status_code == 200
    assert sources.json()[0]["source_name"] == "manual"


def test_feed_sync_uses_normalizer_and_deduplicates(client, monkeypatch):
    import app.routes as route_module
    class FakeResponse:
        text = "# comment\nid,dateadded,url\n1,2026-01-01,https://feed.example/malware\n"
        def raise_for_status(self):
            return None
    monkeypatch.setattr(route_module.requests, "get", lambda *args, **kwargs: FakeResponse())
    response = client.post("/feeds/urlhaus/sync")
    assert response.status_code == 200
    assert response.json()["added"] == 1
    duplicate = client.post("/feeds/urlhaus/sync")
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicates"] == 1

def test_expiry_maintenance_endpoint(client):
    created = client.post("/iocs/", json={
        "indicator": "expired.example", "indicator_type": "domain",
        "severity": "low", "confidence": 50, "source": "test",
        "tlp": "clear", "status": "active", "tags": "[]",
        "attack_techniques": "[]", "first_seen": "2020-01-01T00:00:00",
        "expires_at": "2020-01-02T00:00:00"
    })
    assert created.status_code == 201
    result = client.post("/maintenance/expire")
    assert result.status_code == 200
    assert result.json()["expired"] == 1
    assert client.get(f"/iocs/{created.json()['id']}").json()["status"] == "expired"


def test_dashboard_assets_and_openapi(client):
    page = client.get("/")
    assert page.status_code == 200
    assert 'id="feedSelect"' in page.text
    assert 'id="alertsTable"' in page.text
    js = client.get("/static/app.js")
    assert js.status_code == 200
    assert "loadFeeds" in js.text
    schema = client.get("/openapi.json").json()
    assert "/incidents" in schema["paths"]
    assert "/reports/summary.pdf" in schema["paths"]
