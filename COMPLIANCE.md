# Compliance Posture

This document describes the compliance-relevant controls that are actually present in the repository as of **31 March 2026**. It does **not** claim that this codebase, on its own, delivers ISO/IEC 27001 certification, SOC 2 attestation, or any other formal assurance outcome.

Formal compliance depends on organisational scope, operating procedures, change control, access governance, evidence retention, legal review, audit sampling, and independent assessment. The repository can support those activities, but it does not replace them.

## Practical Position

A fair compliance description for the current project is:

- the codebase contains real security, integrity, logging, and recovery controls that can support an audited deployment
- several important defaults remain permissive until an operator hardens them
- some repository language historically used terms such as "signature" more loosely than the implementation warrants
- symmetric shared-key authentication is used in several places where a stricter environment might expect asymmetric signing or a richer machine identity model

That means the project is best treated as **compliance-supporting software**, not compliance evidence by itself.

## Implemented Control Areas

### Access control and operator authentication

The repository supports OIDC JWT validation for:

- status routes
- TraceyGuard status and control routes
- OTLP HTTP ingest
- OTLP gRPC ingest

This is implemented in `src/auth.rs` and wired through `src/lib.rs`, `src/status.rs`, and `src/telemetry.rs`.

Important caveat: `auth.mode` defaults to `off`. In the shipped default profile, the status and TraceyGuard control routes are therefore unauthenticated unless the operator enables OIDC and supplies a usable OIDC configuration.

### Integrity and change control

The code implements integrity checks for several lifecycle paths.

- OTA update bundles are verified against metadata plus a keyed BLAKE3 MAC in `src/update.rs`.
- The loader verifies the locally active core before promotion or redistribution in `src/loader.rs`.
- The loader maintains a local integrity manifest for the loader binary itself in `loader/tracey-loader.manifest.json`.
- Supervisor and loader hand-off flows require explicit readiness signalling before the previous process is shut down.

Important caveat: the so-called update "signature" is a symmetric keyed digest, not a detached public-key signature.

### Logging and auditability

`src/storage.rs` persists structured JSONL records for operationally significant events and control changes, including:

- `event`
- `decision`
- `learning`
- `ban_update`
- `agent_presence`
- `host_observation`
- `unmanaged_host`
- `tuning_update`
- `update_record`
- `governance_update`
- `log_summary`

This is useful for operational evidence because it records both inputs and important runtime decisions in a consistent append-only format, with bounded retention controls.

### Monitoring and anomaly visibility

The project includes real monitoring and assessment surfaces:

- embedded host and GPU collectors
- Prometheus scrape ingestion and OTLP metric receivers
- Refiner health and finding ingestion
- TraceyGuard fault/probe telemetry
- status snapshots and health routes
- Prometheus pertinent-log export

These capabilities help with control areas usually framed as security monitoring, operational oversight, and incident detection.

### Resilience and recovery

The project contains multiple recovery-oriented features:

- restart supervision in `src/supervisor.rs`
- zero-downtime hand-off for supervised updates
- loader rollback probation windows
- automatic restoration of the previous core if a promoted core fails during probation
- bounded storage rotation and compaction to limit local resource growth

These features support availability-oriented control narratives, provided they are paired with suitable operational procedures and platform-level monitoring.

## Evidence the Repository Can Produce

When operated carefully, the current implementation can contribute evidence such as:

- JSONL runtime records from the configured storage log path
- staged update artefacts and archived applied artefacts under `update.update_dir`
- supervisor request files such as `tracey.supervisor.request.json`
- loader metadata, signatures, rollback state, and archived failed cores under `loader.state_dir`
- loader integrity manifest data in `tracey-loader.manifest.json`
- systemd unit, environment file, and generated JSON config produced by `scripts/install-service.sh`
- TraceyBan persisted state, including offsets and active bans, at `tracey_ban.state_path`

That evidence is technically useful, but it is still only part of a compliance story. An auditor would normally also expect retention policy, ownership, review cadence, tamper controls, and supporting process evidence outside the repository.

## ISO/IEC 27001 Alignment Notes

The following table describes reasonable, code-backed alignment claims. It intentionally avoids claiming full Annex A coverage.

| Area | Code-backed support | Important limitation |
| --- | --- | --- |
| Access control | Optional OIDC validation for status and OTLP surfaces | Disabled by default; `/metrics` is not OIDC-gated |
| Cryptographic integrity | Keyed BLAKE3 MACs for updates, discovery, loader gossip, and Prometheus forwarding | Symmetric trust model; no asymmetric signer identity |
| Logging and monitoring | Structured JSONL audit records, status routes, telemetry ingest, Prometheus export | Retention, review, and alert handling are operational responsibilities |
| Secure change deployment | Staged update verification, supervisor hand-off, loader promotion and rollback | Release governance and key custody sit outside the codebase |
| Operational resilience | Supervisor restarts, rollback probation, bounded storage | Backup, disaster recovery policy, and service objectives are external |
| Network security support | Configurable bind addresses, optional route protection, shared-key authenticated gossip | Many default surfaces are exposed or unauthenticated until hardened |

## SOC 2 Trust Services Notes

### Security

The code supports the Security criterion through authentication hooks, integrity verification, bounded inputs, and structured operational logging. The main weakness is the default-open posture of some HTTP surfaces until OIDC or external network controls are applied.

### Availability

Supervisor restarts, hand-off logic, loader rollback, and storage bounding support availability-oriented controls. They do not by themselves define recovery objectives, staffing, escalation processes, or capacity policy.

### Confidentiality

Confidentiality support is limited and deployment-dependent. The status server and loader transfer server are plain HTTP unless you add TLS externally. Discovery gossip is authenticated but not encrypted. Any confidentiality claim therefore depends heavily on network placement, transport wrapping, and secrets handling outside the repository.

### Processing integrity

Processing integrity is one of the stronger areas in the current implementation. The system normalises events, records outcomes, validates update artefacts, and preserves rollback state. The principal caveat is that integrity relies on symmetric shared secrets in several workflows.

## Known Exclusions and External Dependencies

The repository does not, by itself, provide:

- formal policy management or an information security management system
- joiner, mover, leaver, or privileged-access review processes
- central secret-management, rotation workflow, or hardware-backed key custody
- vulnerability management policy, patch SLA governance, or independent penetration testing
- backup scheduling, restore testing, or retention-policy enforcement outside local runtime files
- privacy classification, lawful-basis assessment, or records-of-processing obligations
- supplier assurance, contractual controls, or change-approval workflow
- independent audit evidence, control attestations, or signed certifications

If those outcomes matter, they must be designed and evidenced in the surrounding platform and organisation.

## Recommended Documentation Language

When describing this repository in procurement, audit, or governance material, use language such as:

- "supports authenticated operator access through optional OIDC"
- "supports update integrity verification using keyed BLAKE3 MACs"
- "supports structured operational evidence through bounded JSONL audit logs"
- "supports supervised promotion and rollback of mutable runtime binaries"

Avoid language such as:

- "ISO 27001 compliant" without a defined scope and independent assessment
- "SOC 2 certified" or "SOC 2 compliant" unless an attestation actually exists
- "digitally signed updates" if the review expects asymmetric signing semantics
- "secure by default" for the repository’s default network profile
