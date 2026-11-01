# PRD v1.0 Traceability — ThreatLens MVP

This matrix maps the supplied ThreatLens PRD v1.0 to the code in this repository. Status means implemented and demonstrable in this repository, not production-certified.

**Legend:** Implemented = working code and tests/UI/API; Partial = a narrower MVP implementation exists; Pending = not implemented; External = depends on provider credentials or infrastructure and is not guaranteed by local tests.

## Functional requirements

| ID | PRD capability | Status | Evidence / limitation |
|---|---|---|---|
| FR-01 | At least six independent public/private feeds | Partial / External | Six connectors catalogued; five public feeds plus OTX requiring API key. No independent scheduler yet. |
| FR-02 | Normalize JSON, CSV and STIX records | Partial | Normalizers for Feodo JSON, abuse.ch CSV, CISA JSON and OTX JSON. TAXII/STIX ingestion not implemented. |
| FR-03 | Canonical deduplication and per-source provenance | Implemented | Unique IOC indicator and `indicator_sources` table. |
| FR-04 | TAXII 2.1 collections | Pending | No TAXII client. |
| FR-05 | Feed add/disable/re-poll from UI | Partial | Six fixed connectors and manual sync selector; no arbitrary feed CRUD or disable controls. |
| FR-06 | IP/domain/URL/hash/email/CVE lifecycle | Implemented | Validated IOC CRUD, timestamps and lifecycle status. |
| FR-07 | Tags, TLP, ATT&CK IDs, analyst notes | Implemented | Persisted IOC metadata and form fields. |
| FR-08 | Configurable TTL and automatic aging | Partial | Expiry fields and manual `POST /maintenance/expire`; no scheduler. |
| FR-09 | IOC relationships | Pending | No relationship graph/table yet. |
| FR-10 | IP reputation aggregation | Pending | No reputation provider integration. |
| FR-11 | Malicious-domain analysis | Pending | URLhaus/ThreatFox feeds can ingest indicators; no domain reputation analysis. |
| FR-12 | Malware hash engine verdict ratios | Pending | MalwareBazaar hash ingestion only; no multi-engine verdict ratio. |
| FR-13 | Reproducible 0–100 score | Partial | Tested severity × confidence baseline; no recency or multi-source weighting. |
| FR-14 | Geolocation and ASN | Pending | No GeoIP/ASN provider. |
| FR-15 | Real-time WebSocket alerts | Pending | Alerts are persisted and polled via REST; no WebSocket gateway. |
| FR-16 | Correlate indicators against internal events | Partial | Exact indicator matching against ingested internal events. No SIEM event parser or fuzzy correlation. |
| FR-17 | Configurable alert rule engine | Partial | High-score and correlation-generated alerts; no user-defined rules. |
| FR-18 | Alert lifecycle and assignee | Implemented | new → acknowledged → in-progress → resolved → closed; REST update. |
| FR-19 | Append-only incident timeline | Partial | Incident timeline entries append through API; no automatic full incident graph or DB immutability guarantees. |
| FR-20 | Global geographic heatmap | Pending | No geolocation dataset/map. |
| FR-21 | Trend/category/source/severity charts | Partial | Live severity and IOC-type charts; no historical time-series/source trend. |
| FR-22 | Custom dashboard widgets/layouts | Pending | Static responsive dashboard. |
| FR-23 | Scheduled and on-demand PDF reports | Partial | On-demand PDF summary; no scheduler or advanced executive narrative. |
| FR-24 | STIX 2.1 and CSV export | Partial | CSV and STIX 2.1 bundle-style export with TLP ceiling; no formal STIX validator/conformance test. |
| FR-25 | Full-text/faceted search | Partial | Search and filters across IOC value/source/notes in the dashboard/API; not Elasticsearch or event-wide search. |
| FR-26 | Server-enforced RBAC | Pending | No login/JWT or role enforcement in this MVP. |
| FR-27 | Immutable audit for every state change | Partial | Audit events for implemented write operations; SQLite table is not tamper-evident/immutable. |
| FR-28 | Authenticated REST and WebSocket APIs | Partial | REST/OpenAPI available; no JWT authentication or WebSocket. |
| FR-29 | SIEM/EDR/ticketing webhooks | Pending | Internal event ingestion endpoint only; no outbound vendor connectors. |

## Non-functional requirements

| ID | PRD target | Status |
|---|---|---|
| NFR-01 | Dashboard <2s; API p95 <400ms | Not benchmarked |
| NFR-02 | WebSocket alert delivery <5s | Pending — no WebSocket |
| NFR-03 | 50,000 ingests/hour and 200 concurrent users | Not load-tested |
| NFR-04 | 99.5% monthly availability | Not measured |
| NFR-05 | Search p95 <800ms over 10M+ docs | Not applicable — SQLite demo, not load-tested |
| NFR-06 | TLS 1.2+ and AES-256 at rest | Deployment responsibility; not provided by local demo |
| NFR-07 | Restart-safe/idempotent ingestion | Partial — SQLite persistence and deduplication; feed replay not exhaustively tested |
| NFR-08 | ≥80% core test coverage | Not measured; current tests are functional tests, no coverage claim |
| NFR-09 | Triage workflow ≤4 clicks | Not formally usability-tested |
| NFR-10 | Structured logs, health and metrics | Partial — health and counters; no central log aggregation |
| NFR-11 | Docker Compose and Kubernetes | Partial — Docker Compose; Kubernetes manifests pending |
| NFR-12 | One-year audit retention and least privilege | Pending — no retention policy or RBAC |

## Security notes

- Do not expose the unauthenticated demo API to the public internet.
- Do not use this MVP to make automatic blocking or containment decisions.
- Feed records are untrusted; verify indicators with approved sources.
- OTX key is read from `OTX_API_KEY`; never commit `.env`.
- TLP red indicators are excluded from exports by default. The default STIX export ceiling is `amber`; CSV/PDF exclude red records.
- Use production-grade authentication/RBAC, TLS, rate limiting, secrets management, immutable audit storage and a security review before deployment.

## Verification performed for this package

- Python bytecode compilation.
- JavaScript syntax check with Node.js.
- Pytest suite covering scoring, IOC validation, API CRUD, feed catalog, CISA/URLhaus parser fixtures, correlation, alert lifecycle, incident timeline, provenance, STIX TLP filtering and CSV/PDF exports.
- Live provider availability and feed freshness are not claimed by offline tests.
