# Security Notes

This document describes the security mechanisms that are actually present in the repository as of **7 April 2026**. It is intentionally narrower and more precise than a marketing-style security overview.

The project contains meaningful controls, but it is not secure by default in every deployment shape. Several network surfaces are enabled or reachable without authorisation until you explicitly harden them.

## Security Model in Plain Terms

Tracey currently relies on three different trust patterns.

### 1. Optional OIDC for operator-facing HTTP and OTLP routes

`src/auth.rs` implements an `AuthGate` that can protect:

- status routes
- TraceyGuard status and control routes
- OTLP HTTP ingest
- OTLP gRPC ingest

Important defaults:

- `auth.mode` defaults to `off`
- `protect_status` defaults to `true`, but has no effect while auth mode is off
- `protect_otlp_http` defaults to `true`, but again only matters once auth mode is enabled
- `protect_otlp_grpc` defaults to `false`

In other words, the code supports OIDC, but it does not enable it automatically.

### 2. Shared-key MACs for distributed internal trust

Several subsystems authenticate payloads with keyed BLAKE3 digests derived from shared secrets:

- discovery gossip
- update bundle verification
- Prometheus exporter follower forwarding
- loader gossip announcements

This is a **symmetric** trust model.

Security implications:

- authenticity depends entirely on the secrecy of the shared key
- there is no per-peer public/private key identity model
- anyone holding the key can forge an apparently valid peer payload
- traffic is authenticated but not encrypted

### 3. Local process and filesystem controls

The runtime also uses:

- cooperative shutdown tokens for handoff and controlled stop
- JSONL audit records for events and control changes
- rollback markers and archived artefacts for loader recovery
- file-based state for TraceyBan offsets and active bans

## Implemented Security Controls

### OIDC JWT validation

When `auth.mode=oidc` and OIDC settings are present, the validator:

- supports issuer discovery through `/.well-known/openid-configuration`
- caches discovery and JWKS data with TTLs
- validates token expiry and optional issuer/audience constraints
- supports required scope checks
- accepts only asymmetric algorithms such as `RS*`, `ES*`, `PS*`, and `EdDSA`
- rejects unsupported algorithms such as `HS256`

This is a solid control for user- or service-facing route protection, but it must be switched on deliberately.

### Constant-time digest comparisons

The code implements constant-time equality checks for digest comparison in several places, reducing straightforward timing leakage when checking signatures or MACs.

### Input validation and sanitisation

The repository validates and bounds several untrusted payloads:

- discovery announcements
- status proxy snapshots
- Slurm snapshot fields before advertisement
- loader announcements
- Prometheus exporter batch size and freshness
- TraceyBan ban/fault advertisement contents
- configuration ranges and enablement preconditions

### Update integrity checks

The update path requires:

- metadata that includes version, OS, architecture, hash, and channel
- a keyed BLAKE3 digest over `metadata || bundle`
- an exact OS and architecture match
- a channel match with the local policy channel

The remote-update path additionally requires:

- a CA certificate file
- a client identity file
- a successful HTTPS mTLS session before download

### Loader rollback safety

The loader preserves:

- the previous stable core
- a rollback marker with failed and previous versions and digests
- archived failed cores under staging

This gives the service an actual recovery path instead of simply trusting a new binary once it has launched.

### Bounded persistence and queues

Resource-bounding is also a security and resilience concern. The code currently limits:

- storage archive count and total log footprint
- telemetry sample counts
- Prometheus exporter queue depth and batch size
- TraceyGuard snapshot sizes and overhead budget
- discovery advertisement entry counts

## Default Security Posture That Requires Hardening

These are the most important code-backed caveats.

### Status API is open unless you enable OIDC

`status.enabled` defaults to true, `status.listen_addr` defaults to `0.0.0.0:48000`, and `auth.mode` defaults to `off`.

That means the following routes are open by default unless you add network controls or enable OIDC:

- `/status`
- `/health`
- `/ready`
- `/tracey_guard`
- `/tracey_guard/deepdive`
- `/control/tracey_guard`

If that is unacceptable in your environment, move the bind address to loopback immediately or place the service behind a reverse proxy or service mesh with transport security and authentication.

### `/metrics` is not OIDC-gated

The Prometheus exposition route does not call `AuthGate` at all.

Current behaviour:

- if the Prometheus exporter handle exists, `/metrics` is available
- authorisation is left to network placement, reverse proxies, or platform controls

Treat it as an unauthenticated metrics surface.

### `/prometheus/ingest` uses a shared-key MAC, not user auth

Follower forwarding batches are authenticated through `x-tracey-prometheus-signature`, not OIDC.

That is adequate for cluster-internal integrity if the shared key is secret and the network is constrained, but it is not a substitute for broader service authentication or transport encryption.

### Discovery is authenticated but not encrypted

Discovery gossip uses shared-key MACs over broadcast UDP payloads. It does not provide confidentiality.

Operationally, that means:

- the broadcast domain must be trusted or segmented
- default development keys must never be used outside local experiments
- gossip contents such as advertised addresses, capability tags, and operational metadata should be treated as visible to the local segment

### Loader transfer is plain HTTP

The loader transfer server serves metadata, signature, and bundle bytes over HTTP.

Security characteristics of the current design:

- confidentiality is not provided by the transfer server itself
- integrity is checked after download via the keyed digest
- only distributable production cores are exposed
- development-channel nodes do not redistribute their core automatically

If bundles should not be visible in plaintext on the network, add TLS outside the loader or keep transfer traffic on a tightly controlled internal network.

### Update “signatures” are symmetric keyed digests

The repository often uses the word “signature” for update artefacts, but the implementation is a symmetric keyed BLAKE3 digest, not a detached public-key signature.

That distinction matters for security review and compliance language:

- compromise of the shared key allows both signing and verification impersonation
- there is no separate signer identity
- key distribution and rotation become central operational controls

### TraceyBan can execute arbitrary configured shell commands

TraceyBan action hooks (`action_start`, `action_stop`, `action_ban`, `action_unban`) are literal shell commands built from configuration templates.

Additional risk factors:

- the runtime may auto-elevate via `sudo`
- actions can run through `sudo` even when the main process is not root
- user-supplied or poorly reviewed config becomes highly privileged behaviour

Treat TraceyBan configuration as privileged code.

## Key Management Guidance

### Discovery and loader gossip keys

Rotate `discovery.shared_key` before any multi-host deployment.

Why this matters:

- discovery authenticity depends on it
- loader gossip may also depend on it when a separate update key is not present
- the repository warns on the development placeholder, but it does not stop you from using it

### Update key

`update.shared_key` protects:

- local staged update verification
- remote mTLS-fetched bundle verification
- loader artefact verification when it uses the update key as the artefact key

Treat this key as release-signing material within the current symmetric trust model.

### Prometheus export signing key

The Prometheus exporter derives its signing key from the discovery shared key passed in from the main runtime bootstrap.

This means a discovery-key compromise can also affect pertinent-log forwarding authenticity.

## Network-Surface-Specific Notes

### Status and TraceyGuard control plane

Recommended hardening steps:

1. bind to loopback unless remote access is genuinely needed
2. enable OIDC and test both status and OTLP paths explicitly
3. add TLS at a reverse proxy, ingress controller, or service mesh layer
4. restrict `/control/tracey_guard` to a minimal operator audience

### Discovery and loader gossip

Recommended hardening steps:

1. place nodes on a dedicated management segment or VLAN
2. rotate shared keys and distribute them through a proper secret-management path
3. disable discovery entirely if you do not need peer presence or distributed intel

### Loader transfer

Recommended hardening steps:

1. restrict reachability to authorised peers only
2. add TLS termination externally if bundle confidentiality matters
3. monitor transfer endpoints because production cores can be downloaded when distributable

### OTLP and telemetry

Recommended hardening steps:

1. keep OTLP listeners on loopback unless there is a specific remote-ingest design
2. enable OIDC before opening OTLP listeners beyond a trusted local host
3. review the allowlist settings so Tracey only accepts metrics it is expected to process

## Logging, Audit, and Evidence Value

The JSONL storage stream can support security operations and later audit review because it records:

- raw events from multiple producers
- final decisions
- governance updates
- tuning updates
- update records
- TraceyBan ban updates
- discovery-derived agent presence
- asset and unmanaged-host observations

Important caveats:

- this is an audit aid, not a tamper-proof ledger
- the log is bounded and may rotate or compact older data away
- if you need long-term retention, forward or archive it externally

## Current Gaps and Limitations

The following points are grounded directly in the current code.

### Synthetic activity can obscure “real-only” operation

The runtime always starts synthetic sensors, and TraceyGuard can synthesise devices and faults. If you require only real host telemetry, the current implementation needs additional configuration discipline or code changes.

### No built-in TLS termination for core HTTP surfaces

Neither the status server nor the loader transfer server terminates TLS natively.

### No RBAC beyond route-level gate choices

OIDC support allows token validation and scope checks, but there is no finer-grained role model within the application itself.

### Shared-key model concentrates trust

Discovery, updates, loader gossip, and exporter forwarding all rely on secrets that can authenticate an entire trust domain. This is operationally simpler than PKI, but it increases the blast radius of key leakage.

### Some safety-sensitive routes remain intentionally exposed

- `/metrics` is exposed when the exporter is present
- `/loader/core/*` routes are exposed when the current core is distributable

Those are not accidental omissions in the documentation; they reflect the actual route handlers in the code.

## Recommended Hardening Checklist

1. Set `discovery.shared_key` and `update.shared_key` to non-default secrets, or disable those subsystems.
2. Move `status.listen_addr` to loopback or place the service behind a protected ingress path.
3. Enable `auth.mode=oidc` and configure issuer, audiences, and scopes before exposing status or OTLP routes.
4. Disable the Prometheus exporter if you do not need pertinent-log aggregation or external probe traffic.
5. Review whether TraceyGuard synthetic behaviour and always-on synthetic sensors are appropriate for the target environment.
6. Treat TraceyBan configuration and action templates as privileged code and prefer system-scope service installs when root access is genuinely required.
7. Add TLS externally for status and loader transfer traffic whenever those surfaces cross host or trust boundaries.
8. Forward or archive JSONL logs externally if retention or tamper evidence matters.
