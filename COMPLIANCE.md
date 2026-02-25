# Compliance Posture (ISO 27001 / SOC 2)

This project includes security controls that support ISO 27001 and SOC 2 alignment. It does not, by itself, confer certification. Compliance depends on organizational policies, audits, and evidence collection.

## Scope
- Swarm runtime, governance, and coordination.
- Status and telemetry interfaces.
- OTA update verification and supervisor handoff.

## Control Highlights
- Access control: OIDC enforcement for external interfaces.
- Integrity: signed update bundles and safe handoff.
- Logging: JSONL audit trails for decisions and governance.

## ISO 27001 Alignment Notes
- Identity and access: OIDC support and policy-based enforcement.
- Cryptography: TLS expected at the edge; signed updates for integrity.
- Logging and monitoring: structured logs and telemetry ingestion.

## SOC 2 Trust Services Alignment Notes
- Security: authentication controls and auditability.
- Availability: supervisor mode and safe OTA handoff.
- Confidentiality: minimize sensitive data in logs and storage.

## Evidence Collection Suggestions
- Retain update signatures, configuration snapshots, and governance logs.
- Document access reviews and incident procedures outside this repository.
