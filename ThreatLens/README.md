# ThreatLens — Cyber Threat Intelligence Dashboard

**Sentinova Security Systems | Demonstration MVP | Version 1.1.0**

ThreatLens is a FastAPI-based cyber threat intelligence dashboard for collecting, validating, deduplicating, scoring and managing Indicators of Compromise (IOCs). It includes a browser dashboard, public-feed connectors, IOC provenance, alert lifecycle management, internal-event correlation, incident timelines, audit events and export workflows.

> **Scope and accuracy:** The supplied 26-page PRD v1.0 describes an enterprise platform planned over four weeks. This repository is a runnable, single-engineer demonstration MVP. It implements a broad vertical slice of the PRD, but it is **not** a production SOC platform and does not claim every PRD requirement or production target is complete. See `docs/PRD_TRACEABILITY.md` for the requirement-by-requirement status.

## Implemented capabilities

### IOC lifecycle and analysis
- Create, list, retrieve, update and delete IP, domain, URL, MD5/SHA-1/SHA-256, email and CVE indicators.
- Validate indicator syntax at the API boundary.
- Deduplicate canonical indicators and retain source provenance.
- Store confidence, TLP, lifecycle status, first/last-seen and expiry timestamps, tags, MITRE ATT&CK IDs and analyst notes.
- Calculate a reproducible score: `round(base severity × confidence / 100)`.
- Expire due indicators through `POST /maintenance/expire`.

### Threat intelligence feeds
Six connector definitions are included:
1. Feodo Tracker — public botnet IP blocklist.
2. URLhaus — recent malware-distribution URLs.
3. MalwareBazaar — recent malware hashes.
4. ThreatFox — recent malware-related indicators.
5. CISA KEV — known exploited CVEs.
6. AlienVault OTX — API-key-based indicator export (`OTX_API_KEY` required).

Five feeds use public downloads; OTX requires an API key. Feed connectivity, upstream format and availability depend on the providers and the network at sync time. The app records each run's fetched, added, duplicate and invalid counts. Feed records are untrusted intelligence; verify them before operational use.

### SOC workflows
- Automatically create review alerts for high-score IOCs and feed ingests.
- Manage alert states: `new`, `acknowledged`, `in-progress`, `resolved`, `closed`; assign an analyst.
- Ingest internal security events and correlate exact indicator matches.
- Create incidents and append analyst/system entries to incident timelines.
- Review audit events for implemented state-changing workflows.

### Dashboard and exports
- Responsive dark dashboard with IOC search and facets, summary cards, severity/category charts, recent activity and feed history.
- CSV export from the dashboard and `/export/csv`.
- STIX 2.1 bundle-style export from `/export/stix`; by default, red-TLP indicators are excluded (`max_tlp=amber`). Choose a lower maximum TLP class to restrict further.
- On-demand PDF summary from `/reports/summary.pdf`.
- OpenAPI documentation at `/docs`, ReDoc at `/redoc`, health at `/health`, operational counters at `/metrics`.

## Technology

| Layer | Technology |
|---|---|
| API | Python 3.12+, FastAPI, Uvicorn |
| ORM / persistence | SQLAlchemy 2, SQLite by default |
| Validation | Pydantic 2 |
| Frontend | HTML, CSS, vanilla JavaScript |
| Charts | Chart.js 4 (CDN) |
| HTTP feed clients | Requests |
| PDF | ReportLab |
| Tests | Pytest, FastAPI TestClient, HTTPX |
| Container | Docker, Docker Compose |

SQLite is the local/demo default. The database URL is configurable using `DATABASE_URL`; PostgreSQL can be selected with a compatible SQLAlchemy URL and driver, but PostgreSQL deployment has not been load-tested in this project.

## Quick start — Windows

1. Install Python 3.12 or newer.
2. Extract the repository.
3. Copy `.env.example` to `.env` if you need to configure OTX.
4. Double-click `run.bat`, or run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

If PowerShell blocks environment activation:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Open:
- Dashboard: http://127.0.0.1:8000
- API docs: http://127.0.0.1:8000/docs
- ReDoc: http://127.0.0.1:8000/redoc
- Health: http://127.0.0.1:8000/health

The SQLite database is created automatically on first launch. Existing databases are migrated additively; back up a valuable database before upgrading.

## Configure AlienVault OTX

1. Obtain an OTX API key from your OTX account.
2. Copy `.env.example` to `.env`.
3. Set `OTX_API_KEY=your_key` in `.env`.
4. Restart the app and select AlienVault OTX from the feed selector.

Do not commit `.env` or API keys. `.env` is excluded by `.gitignore`.

## Run with Docker

Install and start Docker Desktop, then run from the repository root:

```bash
docker compose up --build
```

Open http://localhost:8000. Docker Compose stores the SQLite database in a named volume.

## Run tests

```powershell
pytest -q
```

The suite tests IOC scoring and validation, feed catalog availability, CISA/URLhaus feed parsing, IOC CRUD, event correlation, alert lifecycle, incident timeline, provenance and CSV/PDF/STIX exports. It does not test live third-party feed availability, penetration resistance, load targets or production deployment.

## API overview

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Health check |
| GET/POST | `/iocs/` | List/create IOCs |
| GET/PUT/DELETE | `/iocs/{id}` | Read/update/delete IOC |
| GET | `/iocs/{id}/sources` | Source provenance |
| GET | `/dashboard/summary` | Dashboard aggregates |
| GET | `/feeds` | Six-feed catalog |
| POST | `/feeds/{feed_key}/sync` | Sync a configured feed |
| GET | `/iocs/feeds/history` | Feed run history |
| GET | `/alerts` | List alerts |
| PATCH | `/alerts/{id}` | Update alert lifecycle/assignee |
| POST/GET | `/events` | Ingest/list internal security events |
| POST/GET | `/incidents` | Create/list incidents |
| GET/POST | `/incidents/{id}/timeline` | Read/append timeline entries |
| POST | `/maintenance/expire` | Expire indicators past TTL |
| GET | `/export/csv` | CSV export |
| GET | `/export/stix` | STIX 2.1 bundle-style export |
| GET | `/reports/summary.pdf` | PDF summary |
| GET | `/audit` | Recent audit events |
| GET | `/metrics` | Operational counters |

All request and response schemas are visible in `/docs`.

## Scoring model

| Severity | Base score |
|---|---:|
| Low | 20 |
| Medium | 50 |
| High | 75 |
| Critical | 100 |

`threat_score = round(base_severity_score × confidence / 100)`

Example: High severity at 85% confidence produces `round(75 × 0.85) = 64`.

This is a transparent baseline, not a calibrated threat-intelligence model. It does not yet aggregate multiple vendor verdicts, recency decay or internal sighting weights.

## Security and safe operation

- This demonstration build does **not** implement JWT login, refresh-token rotation, MFA or server-enforced RBAC. Do not expose it to the public internet or use it as a production SOC system.
- Security headers are set by the FastAPI middleware. They are baseline headers, not a substitute for a hardened reverse proxy, TLS, CSP tuning, rate limiting and an application security review.
- `.env` and local databases are excluded from version control. Use a secret manager in production.
- The audit log is append-oriented at the application workflow level, but is not tamper-evident against database administrators or direct database modification.
- TLP-aware exports exclude red-marked records by default. Confirm handling rules with your organisation before sharing intelligence.
- The application records and exports intelligence; it does not block, quarantine or change production infrastructure.
- No malware samples are executed or detonated.

## Known gaps against the supplied PRD

The largest outstanding requirements are JWT/RBAC and MFA; TAXII 2.1 ingestion; feed scheduling and UI feed administration; reputation/domain/hash enrichment; geolocation/ASN; WebSocket push; configurable alert rules and per-user routing; richer incident-to-IOC relationship management; global heatmap; role-specific Executive/SOC/IR/Hunting dashboards; custom dashboard layouts; report scheduling; SIEM/EDR/ticketing webhooks; immutable database-level audit; rate limiting; CI security scanning; Kubernetes manifests; performance and availability validation. The full traceability matrix is in `docs/PRD_TRACEABILITY.md`.

## Project structure

```text
ThreatLens/
├── app/
│   ├── __init__.py
│   ├── database.py
│   ├── main.py
│   ├── migrate.py
│   ├── models.py
│   ├── routes.py
│   └── schemas.py
├── static/
│   ├── app.js
│   ├── index.html
│   └── style.css
├── tests/
│   ├── test_api.py
│   ├── test_core.py
│   └── test_feeds.py
├── docs/
│   └── PRD_TRACEABILITY.md
├── .env.example
├── .gitignore
├── Dockerfile
├── docker-compose.yml
├── README.md
├── requirements.txt
└── run.bat
```

## Demonstration walkthrough

1. Start the app and open the dashboard.
2. Add a reserved documentation IOC such as `198.51.100.25`; this is a test IP, not a malicious host.
3. Set severity, confidence, TLP and ATT&CK metadata; verify the calculated score.
4. Edit the IOC, search/filter it and export CSV/STIX/PDF.
5. Select Feodo Tracker, URLhaus, MalwareBazaar, ThreatFox or CISA KEV and run a feed sync when online. OTX requires a key.
6. Submit an internal event using `/docs` with the same indicator to demonstrate correlation and alert creation.
7. Create an incident and append a timeline note using `/docs`.
8. Review alert status, feed history and the audit trail.

## Attribution

Threat intelligence connectors use public services and datasets published by abuse.ch, CISA and AlienVault OTX. Product scope is based on the supplied ThreatLens PRD v1.0.
