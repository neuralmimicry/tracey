# Security Notes

This repository provides security controls that support ISO 27001 and SOC 2 alignment. It does not, by itself, confer certification. Compliance depends on your operating environment, policies, and evidence collection.

## Scope
- Swarm agent runtime and governance logic.
- Status and telemetry interfaces (`/status`, OTLP HTTP/gRPC ingest).
- OTA update verification and supervisor handoff.
- Refiner security tracking via health probes and JSONL vulnerability feed ingestion.

## Authentication and Access Control
- OIDC enforcement is supported for `/status` and OTLP ingest endpoints.
- `NM_AUTH_MODE=oidc` (or `TRACEY_AUTH_MODE=oidc`) enables OIDC validation.
- Bearer tokens are validated against issuer and JWKS, with optional audience and scope checks.

## Secrets and Tokens
- Do not embed secrets in config files or binaries.
- Use environment variables or a secret manager for OIDC configuration.

## Transport Security
- Run HTTP endpoints behind TLS or a service mesh.
- Consider mTLS for internal service-to-service traffic.

## Logging and Auditability
- Operational logs and governance updates are written to JSONL for audit trails.
- Avoid logging raw tokens or PII in production.

## Refiner Tracking Controls
- Health tracking: periodic checks against Refiner `/api/health` to detect availability and queue-pressure degradation.
- Security feed tracking: append-only JSONL findings (for example Trivy/Falco transforms) are converted into swarm events with severity mapping.

## Operational Requirements (Outside This Repo)
- Access reviews, least privilege, and credential rotation.
- Vulnerability scanning and patching.
- Incident response and backup/retention procedures.
