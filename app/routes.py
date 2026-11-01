import ipaddress
import json
import re
from datetime import datetime, timezone
import csv
import io
import os
from urllib.parse import urlparse

import requests
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import IOC, IOCSource, FeedSyncRun, AuditLog, Alert, Incident, SecurityEvent, IncidentTimeline
from app.schemas import IOCCreate, IOCResponse

router = APIRouter(tags=["ThreatLens"])
SCORES = {"low": 20, "medium": 50, "high": 75, "critical": 100}
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

def calculate_score(severity: str, confidence: int) -> int:
    return round(SCORES[severity] * confidence / 100)

def validate_indicator(value: str, indicator_type: str) -> str:
    value = value.strip()
    try:
        if indicator_type == "ip":
            ipaddress.ip_address(value)
        elif indicator_type == "domain":
            domain = value.encode("idna").decode("ascii")
            if len(domain) > 253 or not re.fullmatch(
                r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))+",
                domain
            ):
                raise ValueError()
        elif indicator_type == "url":
            parsed = urlparse(value)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                raise ValueError()
        elif indicator_type == "hash":
            if not re.fullmatch(r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})", value):
                raise ValueError()
        elif indicator_type == "email":
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
                raise ValueError()
        elif indicator_type == "cve":
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", value, re.IGNORECASE):
                raise ValueError()
    except (ValueError, UnicodeError):
        raise HTTPException(status_code=422, detail=f"Invalid {indicator_type} indicator")
    return value

def validate_json_list(value: str, field_name: str) -> str:
    try:
        parsed = json.loads(value)
        if not isinstance(parsed, list):
            raise ValueError()
        return json.dumps(parsed)
    except (TypeError, ValueError):
        raise HTTPException(status_code=422, detail=f"{field_name} must be a valid JSON array")

def audit(db: Session, action: str, entity_type: str, entity_id=None, details=None):
    db.add(AuditLog(
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id is not None else None,
        details=json.dumps(details or {}, ensure_ascii=False)
    ))

def record_source(db: Session, item: IOC, source_name: str, confidence=50):
    existing = db.query(IOCSource).filter(
        IOCSource.ioc_id == item.id,
        IOCSource.source_name == source_name
    ).first()
    if existing:
        existing.source_confidence = max(existing.source_confidence or 0, confidence)
    else:
        db.add(IOCSource(ioc_id=item.id, source_name=source_name, source_confidence=confidence))

def prepare_data(data: IOCCreate):
    values = data.model_dump()
    values["indicator"] = validate_indicator(values["indicator"], values["indicator_type"])
    values["tags"] = validate_json_list(values["tags"], "tags")
    values["attack_techniques"] = validate_json_list(values["attack_techniques"], "attack_techniques")
    if values["first_seen"] and values["last_seen"] and values["last_seen"] < values["first_seen"]:
        raise HTTPException(status_code=422, detail="last_seen cannot be earlier than first_seen")
    if values["expires_at"] and values["first_seen"] and values["expires_at"] < values["first_seen"]:
        raise HTTPException(status_code=422, detail="expires_at cannot be earlier than first_seen")
    values["threat_score"] = calculate_score(values["severity"], values["confidence"])
    return values

@router.get("/health")
def health():
    return {"status": "healthy", "service": "ThreatLens API", "timestamp": datetime.now(timezone.utc).isoformat()}

@router.get("/iocs/", response_model=list[IOCResponse], tags=["Indicators"])
def list_iocs(
    search: str | None = None,
    indicator_type: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    tlp: str | None = None,
    source: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(IOC)
    if search:
        query = query.filter((IOC.indicator.contains(search)) | (IOC.analyst_notes.contains(search)))
    if indicator_type:
        query = query.filter(IOC.indicator_type == indicator_type)
    if severity:
        query = query.filter(IOC.severity == severity)
    if status:
        query = query.filter(IOC.status == status)
    if tlp:
        query = query.filter(IOC.tlp == tlp)
    if source:
        query = query.filter(IOC.source == source)
    return query.order_by(IOC.id.desc()).offset(offset).limit(limit).all()

@router.post("/iocs/", response_model=IOCResponse, status_code=201, tags=["Indicators"])
def create_ioc(data: IOCCreate, db: Session = Depends(get_db)):
    values = prepare_data(data)
    existing = db.query(IOC).filter(IOC.indicator == values["indicator"]).first()
    if existing:
        raise HTTPException(status_code=409, detail="Indicator already exists")
    item = IOC(**values)
    try:
        db.add(item)
        db.flush()
        record_source(db, item, item.source, item.confidence)
        if item.threat_score >= 75:
            db.add(Alert(
                ioc_id=item.id,
                title=f"High-risk indicator created: {item.indicator[:180]}",
                severity=item.severity,
                description=f"Manual IOC entry with confidence {item.confidence}."
            ))
        audit(db, "ioc.created", "indicator", item.id, {"indicator_type": item.indicator_type})
        db.commit()
        db.refresh(item)
        return item
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Could not save indicator")

@router.get("/iocs/{ioc_id}", response_model=IOCResponse, tags=["Indicators"])
def get_ioc(ioc_id: int, db: Session = Depends(get_db)):
    item = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return item

@router.put("/iocs/{ioc_id}", response_model=IOCResponse, tags=["Indicators"])
def update_ioc(ioc_id: int, data: IOCCreate, db: Session = Depends(get_db)):
    item = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Indicator not found")
    values = prepare_data(data)
    duplicate = db.query(IOC).filter(IOC.indicator == values["indicator"], IOC.id != ioc_id).first()
    if duplicate:
        raise HTTPException(status_code=409, detail="Indicator already exists")
    try:
        for key, value in values.items():
            setattr(item, key, value)
        record_source(db, item, item.source, item.confidence)
        audit(db, "ioc.updated", "indicator", item.id, {"indicator_type": item.indicator_type})
        db.commit()
        db.refresh(item)
        return item
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Could not update indicator")

@router.delete("/iocs/{ioc_id}", tags=["Indicators"])
def delete_ioc(ioc_id: int, db: Session = Depends(get_db)):
    item = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Indicator not found")
    try:
        audit(db, "ioc.deleted", "indicator", item.id, {"indicator_type": item.indicator_type})
        db.query(IOCSource).filter(IOCSource.ioc_id == item.id).delete(synchronize_session=False)
        db.delete(item)
        db.commit()
        return {"message": "Indicator deleted"}
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Could not delete indicator")

@router.get("/dashboard/summary", tags=["Dashboard"])
def dashboard_summary(db: Session = Depends(get_db)):
    records = db.query(IOC).all()
    return {
        "total": len(records),
        "critical": sum(x.severity == "critical" for x in records),
        "high": sum(x.severity == "high" for x in records),
        "medium": sum(x.severity == "medium" for x in records),
        "low": sum(x.severity == "low" for x in records),
        "active": sum(x.status == "active" for x in records),
        "by_type": {t: sum(x.indicator_type == t for x in records) for t in ["ip", "domain", "url", "hash", "email", "cve"]}
    }

@router.post("/iocs/feeds/feodo/sync", tags=["Feeds"])
def sync_feodo_feed(db: Session = Depends(get_db)):
    run = FeedSyncRun(feed_name="Feodo Tracker", status="running")
    db.add(run)
    db.commit()
    db.refresh(run)
    run_id = run.id
    try:
        response = requests.get(FEODO_URL, timeout=30, headers={"User-Agent": "ThreatLens/1.0"})
        response.raise_for_status()
        records = response.json()
        if not isinstance(records, list):
            raise ValueError("Unexpected Feodo Tracker response format")
        added = duplicates = invalid = 0
        for record in records:
            if not isinstance(record, dict):
                invalid += 1
                continue
            try:
                ip = validate_indicator(record.get("ip_address", ""), "ip")
            except HTTPException:
                invalid += 1
                continue
            existing = db.query(IOC).filter(IOC.indicator == ip).first()
            if existing:
                duplicates += 1
                record_source(db, existing, "Feodo Tracker", 85)
                continue
            item = IOC(
                indicator=ip, indicator_type="ip", severity="high",
                threat_score=calculate_score("high", 85), source="Feodo Tracker",
                confidence=85, tlp="clear", status="active",
                tags=json.dumps(["botnet", "feed:feodo"])
            )
            db.add(item)
            db.flush()
            record_source(db, item, "Feodo Tracker", 85)
            added += 1
        run.status = "success"
        run.fetched, run.added, run.duplicates, run.invalid = len(records), added, duplicates, invalid
        run.completed_at = datetime.now(timezone.utc)
        audit(db, "feed.synced", "feed", run_id, {"feed": "Feodo Tracker", "added": added})
        db.commit()
        return {"status": "success", "feed": "Feodo Tracker", "fetched": len(records),
                "added": added, "duplicates": duplicates, "invalid": invalid}
    except Exception as error:
        db.rollback()
        failed = db.query(FeedSyncRun).filter(FeedSyncRun.id == run_id).first()
        if failed:
            failed.status = "failed"
            failed.error_message = str(error)[:1000]
            failed.completed_at = datetime.now(timezone.utc)
            db.commit()
        raise HTTPException(status_code=502, detail=f"Feodo synchronization failed: {error}")

@router.get("/iocs/feeds/history", tags=["Feeds"])
def feed_history(db: Session = Depends(get_db)):
    runs = db.query(FeedSyncRun).order_by(FeedSyncRun.id.desc()).limit(50).all()
    return [{
        "id": r.id, "feed_name": r.feed_name, "status": r.status,
        "fetched": r.fetched, "added": r.added, "duplicates": r.duplicates,
        "invalid": r.invalid, "error_message": r.error_message,
        "started_at": r.started_at, "completed_at": r.completed_at
    } for r in runs]

@router.get("/export/stix", tags=["Exports"])
def export_stix(max_tlp: str = Query("amber"), db: Session = Depends(get_db)):
    tlp_rank = {"clear": 0, "green": 1, "amber": 2, "red": 3}
    if max_tlp not in tlp_rank:
        raise HTTPException(status_code=422, detail="max_tlp must be clear, green, amber or red")
    objects = []
    for item in db.query(IOC).order_by(IOC.id.asc()).all():
        if tlp_rank.get(item.tlp, 3) > tlp_rank[max_tlp]:
            continue
        pattern_type = {"ip": "ipv4-addr" if ":" not in item.indicator else "ipv6-addr",
                        "domain": "domain-name", "url": "url", "hash": "file",
                        "email": "email-addr", "cve": "vulnerability"}.get(item.indicator_type, "x-threatlens")
        if item.indicator_type == "ip":
            pattern = f"[{pattern_type}:value = '{item.indicator}']"
        elif item.indicator_type == "domain":
            pattern = f"[domain-name:value = '{item.indicator}']"
        elif item.indicator_type == "url":
            pattern = f"[url:value = '{item.indicator}']"
        elif item.indicator_type == "email":
            pattern = f"[email-addr:value = '{item.indicator}']"
        elif item.indicator_type == "hash":
            hash_type = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(len(item.indicator), "SHA-256")
            pattern = f"[file:hashes.'{hash_type}' = '{item.indicator}']"
        else:
            pattern = f"[vulnerability:name = '{item.indicator}']"
        objects.append({
            "type": "indicator", "spec_version": "2.1",
            "id": f"indicator--00000000-0000-4000-8000-{item.id:012d}",
            "created": (item.created_at or datetime.now(timezone.utc)).replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
            "modified": (item.updated_at or item.created_at or datetime.now(timezone.utc)).replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
            "name": item.indicator, "pattern": pattern, "pattern_type": "stix",
            "valid_from": (item.first_seen or item.created_at or datetime.now(timezone.utc)).replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
            "confidence": item.confidence,
            "labels": json.loads(item.tags or "[]"),
            "external_references": [{"source_name": "ThreatLens", "description": f"Severity={item.severity}; score={item.threat_score}; TLP={item.tlp}"}]
        })
    return {"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000001", "objects": objects}

@router.get("/audit", tags=["Governance"])
def get_audit_log(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(get_db)):
    rows = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(limit).all()
    return [{"id": x.id, "action": x.action, "entity_type": x.entity_type,
             "entity_id": x.entity_id, "details": x.details, "created_at": x.created_at} for x in rows]


# Additional PRD-aligned capabilities: feed registry, alerts, event correlation,
# incident workspace, timeline and machine-readable exports.
FEED_CATALOG = {
    "feodo": {
        "name": "Feodo Tracker",
        "description": "Botnet command-and-control IP blocklist.",
        "url": FEODO_URL,
        "auth": "none",
        "enabled": True,
    },
    "urlhaus": {
        "name": "URLhaus",
        "description": "Recent malware distribution URLs.",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "auth": "none",
        "enabled": True,
    },
    "malwarebazaar": {
        "name": "MalwareBazaar",
        "description": "Recent malware file hashes.",
        "url": "https://bazaar.abuse.ch/export/csv/recent/",
        "auth": "none",
        "enabled": True,
    },
    "threatfox": {
        "name": "ThreatFox",
        "description": "Recent malware-related indicators.",
        "url": "https://threatfox.abuse.ch/export/csv/recent/",
        "auth": "none",
        "enabled": True,
    },
    "cisa_kev": {
        "name": "CISA Known Exploited Vulnerabilities",
        "description": "Known exploited CVE catalogue.",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "auth": "none",
        "enabled": True,
    },
    "otx": {
        "name": "AlienVault OTX",
        "description": "Open threat intelligence indicators (API key required).",
        "url": "https://otx.alienvault.com/api/v1/indicators/export",
        "auth": "api_key",
        "enabled": True,
    },
}

def _csv_rows(content: str):
    lines = [line for line in content.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not lines:
        return []
    return list(csv.DictReader(io.StringIO("\n".join(lines))))

def _feed_records(feed_key: str, response):
    records = []
    if feed_key == "feodo":
        payload = response.json()
        for row in payload if isinstance(payload, list) else []:
            records.append((row.get("ip_address"), "ip", 85, "botnet"))
    elif feed_key == "urlhaus":
        for row in _csv_rows(response.text):
            value = row.get("url") or row.get("URL")
            if value:
                records.append((value, "url", 80, "malware-distribution"))
    elif feed_key == "malwarebazaar":
        for row in _csv_rows(response.text):
            value = row.get("sha256_hash") or row.get("md5_hash") or row.get("sha1_hash")
            if value:
                records.append((value, "hash", 85, "malware"))
    elif feed_key == "threatfox":
        for row in _csv_rows(response.text):
            value = row.get("ioc") or row.get("indicator")
            kind = (row.get("ioc_type") or "").lower()
            mapped = "ip" if "ip" in kind else "domain" if "domain" in kind else "url" if "url" in kind else "hash" if "hash" in kind else None
            if value and mapped:
                records.append((value, mapped, 80, "threatfox"))
    elif feed_key == "cisa_kev":
        payload = response.json()
        for row in payload.get("vulnerabilities", []) if isinstance(payload, dict) else []:
            value = row.get("cveID")
            if value:
                records.append((value, "cve", 95, "known-exploited"))
    elif feed_key == "otx":
        payload = response.json()
        items = payload.get("results", []) if isinstance(payload, dict) else []
        type_map = {
            "IPv4": "ip", "IPv6": "ip", "domain": "domain",
            "hostname": "domain", "URL": "url", "FileHash-MD5": "hash",
            "FileHash-SHA1": "hash", "FileHash-SHA256": "hash"
        }
        for row in items:
            kind = type_map.get(row.get("type"))
            value = row.get("indicator")
            if kind and value:
                records.append((value, kind, 75, "otx"))
    return records

def _ingest_feed_records(db: Session, feed_name: str, records):
    added = duplicates = invalid = 0
    for value, kind, confidence, tag in records:
        try:
            value = validate_indicator(value or "", kind)
        except HTTPException:
            invalid += 1
            continue
        existing = db.query(IOC).filter(IOC.indicator == value).first()
        if existing:
            duplicates += 1
            record_source(db, existing, feed_name, confidence)
            continue
        severity = "critical" if confidence >= 95 else "high" if confidence >= 80 else "medium"
        item = IOC(
            indicator=value, indicator_type=kind, severity=severity,
            threat_score=calculate_score(severity, confidence),
            source=feed_name, confidence=confidence, tlp="clear",
            status="active", tags=json.dumps([tag, f"feed:{feed_name.lower().replace(' ', '-')}"])
        )
        db.add(item)
        db.flush()
        record_source(db, item, feed_name, confidence)
        if item.threat_score >= 75:
            db.add(Alert(
                ioc_id=item.id,
                title=f"High-risk indicator ingested: {value[:180]}",
                severity=item.severity,
                description=f"Imported from {feed_name} with confidence {confidence}."
            ))
        added += 1
    return added, duplicates, invalid

@router.get("/feeds", tags=["Feeds"])
def list_feeds():
    return [
        {"key": key, **value, "configured": key != "otx" or bool(os.getenv("OTX_API_KEY"))}
        for key, value in FEED_CATALOG.items()
    ]

@router.post("/feeds/{feed_key}/sync", tags=["Feeds"])
def sync_feed(feed_key: str, db: Session = Depends(get_db)):
    config = FEED_CATALOG.get(feed_key)
    if not config:
        raise HTTPException(status_code=404, detail="Unknown feed")
    if feed_key == "otx" and not os.getenv("OTX_API_KEY"):
        raise HTTPException(status_code=400, detail="Set OTX_API_KEY in your environment before syncing this feed")
    run = FeedSyncRun(feed_name=config["name"], status="running")
    db.add(run)
    db.commit()
    db.refresh(run)
    run_id = run.id
    try:
        headers = {"User-Agent": "ThreatLens/1.1"}
        if feed_key == "otx":
            headers["X-OTX-API-KEY"] = os.getenv("OTX_API_KEY")
        response = requests.get(config["url"], headers=headers, timeout=45)
        response.raise_for_status()
        records = _feed_records(feed_key, response)
        added, duplicates, invalid = _ingest_feed_records(db, config["name"], records)
        run.status = "success"
        run.fetched = len(records)
        run.added = added
        run.duplicates = duplicates
        run.invalid = invalid
        run.completed_at = datetime.now(timezone.utc)
        audit(db, "feed.synced", "feed", run_id, {"feed": config["name"], "added": added})
        db.commit()
        return {
            "status": "success", "feed": config["name"], "fetched": len(records),
            "added": added, "duplicates": duplicates, "invalid": invalid
        }
    except Exception as error:
        db.rollback()
        failed = db.query(FeedSyncRun).filter(FeedSyncRun.id == run_id).first()
        if failed:
            failed.status = "failed"
            failed.error_message = str(error)[:1000]
            failed.completed_at = datetime.now(timezone.utc)
            db.commit()
        raise HTTPException(status_code=502, detail=f"{config['name']} sync failed: {error}")

@router.post("/events", tags=["Correlation"])
def ingest_security_event(payload: dict, db: Session = Depends(get_db)):
    indicator = str(payload.get("indicator", "")).strip()
    event_type = str(payload.get("event_type", "observation"))[:80]
    source = str(payload.get("source", "internal"))[:100]
    if not indicator:
        raise HTTPException(status_code=422, detail="indicator is required")
    event = SecurityEvent(
        indicator=indicator, event_type=event_type, source=source,
        details=json.dumps(payload.get("details", {}), ensure_ascii=False)
    )
    db.add(event)
    db.flush()
    matches = db.query(IOC).filter(IOC.indicator == indicator).all()
    created_alerts = []
    for item in matches:
        alert = Alert(
            ioc_id=item.id,
            title=f"Internal event matched IOC: {indicator[:160]}",
            severity=item.severity,
            description=f"{source} reported {event_type}."
        )
        db.add(alert)
        created_alerts.append(alert)
    audit(db, "event.ingested", "security_event", event.id, {"matches": len(matches)})
    db.commit()
    return {"event_id": event.id, "matched_indicators": len(matches), "alerts_created": len(created_alerts)}

@router.get("/events", tags=["Correlation"])
def list_security_events(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(get_db)):
    rows = db.query(SecurityEvent).order_by(SecurityEvent.id.desc()).limit(limit).all()
    return [{"id": x.id, "indicator": x.indicator, "event_type": x.event_type,
             "source": x.source, "details": x.details, "occurred_at": x.occurred_at} for x in rows]

@router.get("/alerts", tags=["Alerts"])
def list_alerts(status: str | None = None, limit: int = Query(100, ge=1, le=1000), db: Session = Depends(get_db)):
    query = db.query(Alert)
    if status:
        query = query.filter(Alert.status == status)
    rows = query.order_by(Alert.id.desc()).limit(limit).all()
    return [{"id": x.id, "ioc_id": x.ioc_id, "title": x.title, "severity": x.severity,
             "status": x.status, "assignee": x.assignee, "description": x.description,
             "created_at": x.created_at, "updated_at": x.updated_at} for x in rows]

@router.patch("/alerts/{alert_id}", tags=["Alerts"])
def update_alert(alert_id: int, payload: dict, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    status = payload.get("status", alert.status)
    allowed = {"new", "acknowledged", "in-progress", "resolved", "closed"}
    if status not in allowed:
        raise HTTPException(status_code=422, detail=f"status must be one of {sorted(allowed)}")
    alert.status = status
    alert.assignee = str(payload.get("assignee", alert.assignee or ""))[:120] or None
    audit(db, "alert.updated", "alert", alert.id, {"status": status})
    db.commit()
    db.refresh(alert)
    return {"id": alert.id, "status": alert.status, "assignee": alert.assignee}

@router.post("/incidents", tags=["Incidents"])
def create_incident(payload: dict, db: Session = Depends(get_db)):
    title = str(payload.get("title", "")).strip()
    if not title:
        raise HTTPException(status_code=422, detail="title is required")
    incident = Incident(
        title=title[:250], severity=payload.get("severity", "medium"),
        owner=str(payload.get("owner", ""))[:120] or None,
        summary=str(payload.get("summary", ""))[:5000] or None
    )
    if incident.severity not in SCORES:
        raise HTTPException(status_code=422, detail="Invalid severity")
    db.add(incident)
    db.flush()
    db.add(IncidentTimeline(incident_id=incident.id, event_type="created",
                            description=f"Incident created: {incident.title}"))
    audit(db, "incident.created", "incident", incident.id)
    db.commit()
    db.refresh(incident)
    return {"id": incident.id, "title": incident.title, "severity": incident.severity,
            "status": incident.status, "owner": incident.owner, "summary": incident.summary,
            "created_at": incident.created_at}

@router.get("/incidents", tags=["Incidents"])
def list_incidents(db: Session = Depends(get_db)):
    rows = db.query(Incident).order_by(Incident.id.desc()).all()
    return [{"id": x.id, "title": x.title, "severity": x.severity, "status": x.status,
             "owner": x.owner, "summary": x.summary, "created_at": x.created_at} for x in rows]

@router.get("/incidents/{incident_id}/timeline", tags=["Incidents"])
def incident_timeline(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    rows = db.query(IncidentTimeline).filter(
        IncidentTimeline.incident_id == incident_id
    ).order_by(IncidentTimeline.id.asc()).all()
    return [{"id": x.id, "event_type": x.event_type, "description": x.description,
             "actor": x.actor, "created_at": x.created_at} for x in rows]

@router.post("/incidents/{incident_id}/timeline", tags=["Incidents"])
def add_incident_timeline(incident_id: int, payload: dict, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    description = str(payload.get("description", "")).strip()
    if not description:
        raise HTTPException(status_code=422, detail="description is required")
    entry = IncidentTimeline(
        incident_id=incident_id, event_type=str(payload.get("event_type", "note"))[:80],
        description=description[:5000], actor=str(payload.get("actor", "analyst"))[:120]
    )
    db.add(entry)
    audit(db, "incident.timeline_added", "incident", incident_id)
    db.commit()
    db.refresh(entry)
    return {"id": entry.id, "incident_id": incident_id, "description": entry.description,
            "created_at": entry.created_at}

@router.get("/export/csv", tags=["Exports"])
def export_csv(db: Session = Depends(get_db)):
    from fastapi.responses import StreamingResponse
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "indicator", "indicator_type", "severity", "threat_score",
                     "confidence", "source", "tlp", "status", "tags",
                     "attack_techniques", "analyst_notes"])
    for item in db.query(IOC).order_by(IOC.id.asc()).all():
        if item.tlp == "red":
            continue
        writer.writerow([item.id, item.indicator, item.indicator_type, item.severity,
                         item.threat_score, item.confidence, item.source, item.tlp,
                         item.status, item.tags, item.attack_techniques, item.analyst_notes])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=threatlens_iocs.csv"})

@router.get("/reports/summary.pdf", tags=["Reports"])
def pdf_summary(db: Session = Depends(get_db)):
    from fastapi.responses import StreamingResponse
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    records = db.query(IOC).order_by(IOC.threat_score.desc()).all()
    pdf.setTitle("ThreatLens Intelligence Summary")
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(48, height - 52, "ThreatLens Intelligence Summary")
    pdf.setFont("Helvetica", 9)
    pdf.drawString(48, height - 70, f"Generated: {datetime.now(timezone.utc).isoformat()}")
    pdf.drawString(48, height - 86, f"Total indicators: {len(records)}")
    y = height - 120
    pdf.setFont("Helvetica-Bold", 9)
    pdf.drawString(48, y, "Indicator")
    pdf.drawString(290, y, "Type")
    pdf.drawString(350, y, "Severity")
    pdf.drawString(430, y, "Score")
    y -= 16
    pdf.setFont("Helvetica", 8)
    for item in records:
        if item.tlp == "red":
            continue
        if y < 55:
            pdf.showPage()
            y = height - 55
            pdf.setFont("Helvetica", 8)
        pdf.drawString(48, y, item.indicator[:42])
        pdf.drawString(290, y, item.indicator_type)
        pdf.drawString(350, y, item.severity)
        pdf.drawString(430, y, str(item.threat_score))
        y -= 13
    pdf.save()
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/pdf",
                             headers={"Content-Disposition": "attachment; filename=threatlens_summary.pdf"})

@router.get("/metrics", tags=["Operations"])
def metrics(db: Session = Depends(get_db)):
    return {
        "indicators": db.query(IOC).count(),
        "alerts": db.query(Alert).count(),
        "open_incidents": db.query(Incident).filter(Incident.status == "open").count(),
        "feed_runs": db.query(FeedSyncRun).count(),
        "events": db.query(SecurityEvent).count()
    }


@router.get("/iocs/{ioc_id}/sources", tags=["Indicators"])
def ioc_sources(ioc_id: int, db: Session = Depends(get_db)):
    item = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Indicator not found")
    rows = db.query(IOCSource).filter(IOCSource.ioc_id == ioc_id).order_by(IOCSource.id.asc()).all()
    return [{"source_name": row.source_name, "source_confidence": row.source_confidence,
             "first_reported": row.first_reported} for row in rows]

@router.post("/maintenance/expire", tags=["Operations"])
def expire_stale_indicators(db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    rows = db.query(IOC).filter(
        IOC.status == "active",
        IOC.expires_at.isnot(None),
        IOC.expires_at <= now.replace(tzinfo=None)
    ).all()
    for item in rows:
        item.status = "expired"
        audit(db, "ioc.expired", "indicator", item.id, {"indicator": item.indicator})
    db.commit()
    return {"expired": len(rows), "checked_at": now.isoformat()}
