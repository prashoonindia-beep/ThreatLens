# Security Policy

ThreatLens in this repository is a demonstration MVP and is not intended for public internet exposure.

## Reporting a vulnerability

Do not publish credentials, API keys, private intelligence or exploit details in public issue reports. Contact the repository maintainer privately and include a concise description, impact and reproducible steps.

## Deployment warning

The current MVP does not implement JWT authentication, MFA or server-enforced RBAC. Run it only on a trusted local network until those controls are implemented and reviewed. Never store secrets in Git; use environment variables or a secrets manager.
