# Tracey

![Tracey](src/nmtracey.png)

Tracey is an asynchronous swarm runtime for anomaly assessment, posture governance, and controlled response. It combines event ingestion, adaptive fuzzy scoring, multi-agent consensus, elected coordination, bounded JSONL audit storage, and optional update/loader lifecycles for rolling binary replacement.

## Design Intent

The codebase is organised around five main goals:

1. Ingest heterogeneous host, telemetry, security, and external inventory signals without blocking the runtime.
2. Convert those inputs into a shared `Event` model so every downstream subsystem reasons over the same payload shape.
3. Use multiple scoring agents and quorum-based coordination instead of a single detector deciding in isolation.
4. Gate disruptive behaviour through governance posture, elected leadership, and explicit response-policy controls.
5. Preserve a durable, bounded, auditable record of what the runtime saw and what it decided.

## Current Implementation Profile

Tracey already includes real integrations, but it also contains deliberate synthetic exercise paths. In practical terms, the project currently behaves as an experimental operations runtime rather than a finished production appliance.

The current code does all of the following:

- always starts four synthetic sensors (`system_cpu`, `network_flow`, `user_actions`, `automation`)
- enables Linux embedded collectors by default when running on Linux
- enables `TraceyGuard` by default and falls back to synthetic GPU identities when no real devices are discovered
- enables authenticated discovery gossip by default on UDP `47990`
- always attempts Slurm/Continuum environment detection and folds the result into capability tags and status snapshots when a local deployment is detected
- enables the HTTP status surface by default on `0.0.0.0:48000`
- always maintains bounded Continuum telemetry and inferred location snapshots for the status and dashboard surfaces
- leaves `auth.mode` off by default, which means status and TraceyGuard control routes are unauthenticated unless you explicitly enable OIDC
- enables the Prometheus log exporter by default, which probes `https://prometheus.neuralmimicry.ai/-/ready` unless reconfigured or disabled
- ships Continuum assessment and autoscaler integrations, but both sanitize off until a Continuum base URL is configured and the autoscaler also has recruit hosts

That default profile is useful for local evaluation and continuous self-exercise, but it is not a hardened deployment baseline.

## Default-On and Default-Off Subsystems

| Area | Default state | Notes |
| --- | --- | --- |
| Synthetic sensors | On | No configuration flag currently disables them. |
| Embedded collectors | On | Linux-only; publishes CPU, memory, disk, network, process, battery, Jetson, and GPU metrics. |
| TraceyGuard | On | Discovers GPUs where possible, otherwise creates synthetic devices and synthetic probe activity. |
| Discovery gossip | On | Broadcast UDP with a shared-key MAC; default key is a development placeholder. |
| Status API | On | Binds to `0.0.0.0:48000`; authorisation is off until OIDC is enabled. |
| Prometheus log export | On | Depends on status being enabled; exposes `/metrics` and signed `/prometheus/ingest`. |
| Slurm detection | On | Best-effort native and Continuum Podman detection; contributes capability tags and status snapshots when found. |
| Continuum telemetry snapshot | On | Always builds bounded host, GPU, action, and probe telemetry for `/status` and page 3 of the dashboard. |
| Coordination and governance | On | Leader election, proxy selection, and posture voting run automatically. |
| Continuum assessment | Off by effective default | The config struct defaults `enabled=true`, but sanitisation disables it until `continuum_assessment.base_url` or an inherited Continuum URL is available. |
| Continuum autoscaler | Off | Requires a Continuum `base_url` plus non-empty recruit hosts; otherwise sanitisation disables it. |
| Telemetry ingest | Off | Prometheus scraping and OTLP receivers are disabled until configured. |
| Refiner tracking | Off | Health polling and security-feed ingestion are opt-in. |
| Asset feed | Off | JSONL host-observation ingestion is opt-in. |
| TraceyBan | Off | Jail logic, actions, and cross-agent ban intelligence are opt-in. |
| OTA update manager | Off | Local and remote update checks are disabled until configured. |
| Stimuli/AER bridge | Off | UDP AER ingest/egress is disabled until configured. |

## Runtime Entry Points

### `tracey`

Primary runtime entry point.

- `cargo run --bin tracey`
- `cargo run --bin tracey -- --tui`
- `cargo run --bin tracey -- --tui --status http://127.0.0.1:48000 --log-path ./tracey.log.jsonl`
- `cargo run --bin tracey -- --version`
- `cargo run --bin tracey -- sign-update --bundle ./tracey-new --version 0.2.0 --key '<shared-key>'`

`tracey --version` returns the runtime build version, formatted as `major.minor.build`. For source builds, the `build` component is derived from the git commit count, so it advances on each commit. The Cargo package version remains the release-version source of truth for packaging and signed update metadata.

### `tracey --supervisor`

Crash-restart and zero-downtime handoff wrapper around the same runtime binary.

- `cargo run --bin tracey -- --supervisor`

The supervisor watches the child process, consumes staged update requests from `update_dir`, and swaps binaries after the replacement process writes the expected handoff token.

### `tracey-loader`

Separate durable loader binary intended for service deployments.

- `cargo run --bin tracey-loader`
- `cargo run --bin tracey-loader -- --version`

The loader supervises a mutable Tracey core, verifies its own integrity manifest, serves distributable production cores to peers, and rolls back failed promotions during a probation window.

### `tracey --tui`

Preferred operator TUI entrypoint, inspired by `btop` and built around Tracey's status and activity surfaces.

- `cargo run --bin tracey -- --tui`
- `cargo run --bin tracey -- --tui --status http://127.0.0.1:48000 --log-path ./tracey.log.jsonl`
- `cargo run --bin tracey -- --tui --no-log`

`tracey --tui` reads `/status` for governance, coordination, TraceyGuard, Slurm, Continuum autoscaler/assessment/telemetry, loader-threat, and location snapshots, then tails the JSONL storage log for signal history, recent decisions, and hot processes.

When `--status` is omitted, the dashboard prefers a reachable local `tracey` or loader-managed `tracey-core` agent if one is already running, so `--tui` stays attach-only instead of starting duplicate collectors.

No-scheme loopback targets default to `http://`; other no-scheme dashboard targets default to `https://`. The header shows `🔒 https` or `🔓 http` for the active status connection.

The dashboard now has three pages: the original overview, a location page with fuzzy host/site/building/room/network inference plus a text cluster map built from local system facts, discovered peers, capability tags, and observed gossip latency, and a telemetry page for Continuum host, GPU, action, and probe snapshots.

Location confidence improves when the runtime can see direct hints. `TRACEY_SITE`, `TRACEY_BUILDING`, `TRACEY_ROOM`, and `TRACEY_GEO` are consumed automatically, propagated through discovery capability tags, and reused by the location page when peers are close enough to share the same inferred room/building/site.

The dashboard expects at least a `120x33` terminal. Smaller windows render a resize notice instead of a broken layout.

`tracey-top` remains available as a thin compatibility wrapper around the same dashboard.

`tracey --tui --help` and `tracey-top --help` expose the current dashboard flags: `--status`, `--bearer`, `--log-path` or `--no-log`, `--refresh-ms`, and `--tail-bytes`.

## Operator CLI

The main `tracey` binary also exposes a lightweight operator CLI that talks to the same status and control routes used by the dashboard.

- `cargo run --bin tracey -- status`
- `TRACEY_STATUS_ADDR=http://127.0.0.1:48000 cargo run --bin tracey -- tracey-ban status`
- `cargo run --bin tracey -- tracey-ban filters`
- `cargo run --bin tracey -- tracey-ban actions`
- `cargo run --bin tracey -- tracey-ban ban --jail sshd-auth --ip 198.51.100.42 --reason manual`
- `cargo run --bin tracey -- tracey-ban unban --jail sshd-auth --ip 198.51.100.42 --reason cleared`
- `cargo run --bin tracey -- tracey-ban refresh-backend --jail sshd-auth`
- `cargo run --bin tracey -- tracey-guard status`
- `cargo run --bin tracey -- tracey-guard enable`
- `cargo run --bin tracey -- tracey-guard deep-dive on`
- `cargo run --bin tracey -- tracey-guard tmr off`
- `cargo run --bin tracey -- tracey-guard set-overhead --pct 7.5`
- `cargo run --bin tracey -- tracey-guard set-parallelism --count 8`
- `cargo run --bin tracey -- tracey-guard force-scan`

Operator CLI notes:

- `--addr`, `TRACEY_STATUS_ADDR`, `status.public_addr`, and `status.listen_addr` are resolved in that order
- `--token`, `TRACEY_STATUS_TOKEN`, and `TRACEY_AUTH_BEARER` all provide the bearer token for protected status/control routes
- loopback-like addresses without a scheme default to `http://`; non-local addresses default to `https://`
- listener binds such as `0.0.0.0:48000` and `[::]:48000` are rewritten to loopback for local CLI use
- `--json` prints the raw API payload for scripting or troubleshooting

## End-to-End Workflow Summary

1. `Config::load()` assembles defaults, optional JSON from `TRACEY_CONFIG`, environment overrides, and a final sanitisation pass.
2. `run_tracey()` wires shutdown, storage, inventory, channels, governance state, coordination, and optional subsystems.
3. Producers publish `Event` values or inventory records.
4. Swarm agents score events with online baselines and Type-n fuzzy refinement.
5. The coordinator aggregates assessments, finalises decisions on quorum or expiry, and broadcasts learning/directive updates.
6. Governance votes adjust posture, which in turn gates active response, shutdown eligibility, update allowance, and remote telemetry allowance.
7. Discovery shares signed peer presence plus optional ban, fault, Slurm, and Prometheus probe metadata.
8. Status and control endpoints expose the local or proxied view of the cluster.
9. Storage writes JSONL records asynchronously and keeps disk use bounded by rotation or compaction.
10. Optional update, supervisor, and loader paths handle staged binary replacement.

`[WORKFLOW_ANALYSIS.md](WORKFLOW_ANALYSIS.md)` contains the code-backed detailed walkthrough.

## Interfaces and Default Ports

| Surface | Default bind | Protocol | Purpose | Security note |
| --- | --- | --- | --- | --- |
| Status API | `0.0.0.0:48000` | HTTP | `/status`, `/health`, `/ready`, TraceyBan and TraceyGuard views/control, `/metrics`, `/prometheus/ingest` | Open by default unless OIDC is enabled; `/metrics` is never OIDC-gated. |
| Discovery | `0.0.0.0:47990` to broadcast `255.255.255.255:47990` | UDP | Peer presence, capability, ban, fault, Slurm, and Prometheus-probe gossip | Shared-key authenticated, but not encrypted. |
| Loader gossip | `0.0.0.0:47989` | UDP | Loader peer announcements for distributable cores | Shared-key authenticated, not encrypted. |
| Loader transfer | `0.0.0.0:47988` | HTTP | Health, loader status, current core metadata, signature, and bundle | Plain HTTP; integrity is checked after download. |
| Stimuli bridge | `0.0.0.0:48100` | UDP | AER ingress and egress | Disabled by default. |
| OTLP gRPC | `127.0.0.1:4317` | gRPC | OTLP metrics ingest | Disabled by default; OIDC protection is optional and off until auth is enabled. |
| OTLP HTTP | `127.0.0.1:4318` | HTTP | OTLP metrics ingest | Disabled by default; route authorisation only matters when auth is enabled. |

### Status surface routes

When `status.enabled` is true, the Axum server exposes:

- `/status`, `/health`, `/ready`: JSON status snapshots; followers may proxy these to the selected proxy address
- `/tracey_ban`: TraceyBan jail and ban-intelligence status snapshot
- `/control/tracey_ban`: TraceyBan manual ban, unban, and backend refresh control updates
- `/tracey_guard` and `/tracey_guard/deepdive`: TraceyGuard status snapshots
- `/control/tracey_guard`: runtime control updates for TraceyGuard
- `/metrics`: Prometheus exposition for the elected pertinent-log exporter
- `/prometheus/ingest`: signed follower-to-exporter batch intake

The `/status` payload currently carries posture and coordination state plus optional TraceyGuard, Slurm, Continuum autoscaler/assessment/telemetry, loader-threat, and inferred self/peer location snapshots.

The operator CLI subcommands `tracey status`, `tracey tracey-ban ...`, and `tracey tracey-guard ...` are thin wrappers over these same routes.

### Loader transfer routes

When `tracey-loader` is running, the transfer server exposes:

- `/health`
- `/loader/status`
- `/loader/core/metadata`
- `/loader/core/signature`
- `/loader/core/bundle`

The `/loader/status` payload includes the active core version/channel, distributable state, rollback state, and the current loader-threat snapshot.

The bundle-serving routes only respond when the local core is considered distributable, which in the current implementation means a production-channel core with no pending rollback probation.

## Event Producers and Their Roles

| Producer | Module | Default | Output |
| --- | --- | --- | --- |
| Synthetic baseline generators | `src/sensors.rs` | On | Four synthetic `Event` streams for system, network, user, and automation activity |
| Linux embedded collectors | `src/embedded.rs` | On | Host and GPU metrics with normalised signals plus raw values in attributes |
| Prometheus scraper and OTLP receivers | `src/telemetry.rs` | Off | Observability events derived from scraped or pushed metrics |
| Refiner health and finding ingestion | `src/refiner_tracking.rs` | Off | Health and security-feed events |
| TraceyBan jail runtime | `src/tracey_ban.rs` | Off | Ban and unban events plus persisted ban intelligence |
| TraceyGuard runtime | `src/tracey_guard.rs` | On | Synthetic probe and fault events tied to GPU identities |
| Stimuli/AER bridge | `src/stimuli.rs` | Off | Inbound `aarnn` events and outbound AER frames |
| Asset feed | `src/assets.rs` | Off | Host observations into inventory rather than the event bus |
| Discovery | `src/discovery.rs` | On | Agent presence into coordination and inventory rather than the event bus |

## Configuration Model

Configuration precedence is:

`defaults < JSON file from TRACEY_CONFIG < environment overrides < sanitisation`

Important characteristics of the current implementation:

- most environment overrides have both `TRACEY_*` and `NM_*` spellings
- sanitisation clamps unsafe numeric values and disables some subsystems when key prerequisites are missing
- relative filesystem paths are resolved from the current working directory
- installed systemd services deliberately set the working directory to the Tracey state directory, so relative paths land inside the service state tree

A minimal hardened starting point usually needs to:

1. rotate `discovery.shared_key` and `update.shared_key`, or disable those subsystems
2. move `status.listen_addr` to loopback or place it behind a reverse proxy
3. enable OIDC if the status or OTLP surfaces are reachable beyond a tightly controlled network
4. decide whether synthetic sensors, TraceyGuard synthetic fallback, and Prometheus exporter probing are acceptable for the environment
5. disable any default-on subsystem that is not wanted operationally

See `[docs/CONFIGURATION_REFERENCE.md](docs/CONFIGURATION_REFERENCE.md)` for a detailed section-by-section reference.

## Storage, Files, and Persistence

### Standard runtime

By default the main runtime writes JSONL records to `tracey.log.jsonl` and may create archive files such as `tracey.log.jsonl.1`, `tracey.log.jsonl.2`, and so on.

Record types currently written by storage are:

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
- `log_summary` (inserted during in-place compaction)

### Update manager

The OTA update path uses `update.update_dir` and expects:

- `tracey.update`
- `tracey.update.meta.json`
- `tracey.update.sig`

### Loader state tree

`tracey-loader` uses `loader.state_dir` and maintains, among other files:

- `loader/current/tracey-core`
- `loader/current/tracey-core.meta.json`
- `loader/current/tracey-core.sig`
- `loader/rollback/tracey-core.previous*`
- `loader/staging/*`
- `loader/tracey-loader.manifest.json`
- `loader/tracey-loader.rollback.json`
- `loader/tracey-loader.threats.state.json`
- `loader/tracey-loader.threats.snapshot.json`

## Update and Loader Behaviour

### Main runtime update manager

The built-in update manager can:

- read a locally staged bundle from `update_dir`
- optionally download metadata, bundle, and signature over HTTPS with mTLS
- verify metadata and bundle integrity using a keyed BLAKE3 digest
- reject OS, architecture, or channel mismatches
- perform direct handoff when unsupervised
- write a supervisor request when running under `TRACEY_SUPERVISED`

### Supervisor mode

`tracey --supervisor` keeps the runtime in a child process, restarts it on exit, and handles zero-downtime handoff when a staged update request appears.

### Loader mode

`tracey-loader` adds a longer-lived service model:

- verifies the loader binary against its local integrity manifest
- seeds metadata and signature for an existing core if only the binary is present
- announces current production-core metadata over UDP gossip
- serves current production cores over HTTP to peers
- fetches newer production cores from peers, verifies them locally, and hands over without stopping the service
- maintains a rollback probation window before redistributing a newly promoted core
- restores the previous signed core automatically when a newly promoted core crashes during probation
- records suspicious provider and artifact incidents in loader-threat state and exposes the current summary through `/loader/status`

A new loader deployment must be bootstrapped with a core binary at `loader/current/tracey-core`. If metadata and signature are missing, the loader generates them locally using the configured shared key.

## Service Installation Script

`scripts/install-service.sh` automates Linux `systemd` installation.

What the script does in the current implementation:

- resolves or builds `tracey` and `tracey-loader`
- installs a PATH-visible `tracey` command for CLI and `tracey --tui` access
- installs `tracey-loader` as the service entry point
- installs a mutable Tracey core into the state directory
- writes a minimal JSON config with `agent_id`, `update.local_channel`, `loader.state_dir`, and optional `bootstrap_version`
- writes an optional environment file for later overrides
- writes a `systemd` unit with `WorkingDirectory` set to the Tracey state directory
- resolves the effective `status.listen_addr` and, when it is not loopback-only, checks the local firewall and opens the status TCP port when `ufw` or `firewalld` is active
- enables and optionally starts the service
- in system scope, prefers `sudo` and disables a conflicting user-scope Tracey service when necessary

The installer-written JSON config also overrides `prometheus_log_export.server_url` to `http://prometheus.neuralmimicry.ai`, which differs from the compiled `https://` default unless an existing config is preserved.

See `[docs/OPERATIONS.md](docs/OPERATIONS.md)` for operational detail.

## GitHub Release Workflow

GitHub Actions release automation lives in `.github/workflows/build-and-release.yml`.

Current behavior:

- every pull request and push to `main` runs the Rust verification job
- the verification job also smoke-tests `tracey --tui --help` and shell-syntax checks the release scripts
- pushing a `v*` tag packages release artifacts for Linux x86_64/aarch64, macOS x86_64/aarch64, Windows x86_64, iOS arm64, and Android arm64, then publishes a GitHub release
- manual `workflow_dispatch` runs can package artifacts from any ref
- manual publishing is allowed only when the workflow is run against a `v*` tag ref and `publish_release` is enabled
- release packaging emits per-platform archives plus checksum files; Linux packages also include optional signed `tracey.update` bundles when signing is enabled
- iOS and Android outputs are raw target binaries packaged for distribution and testing, not signed app-store bundles

If the repository secret `TRACEY_UPDATE_KEY` is configured, tagged releases automatically attach signed update artifacts compatible with the loader/update pipeline.

## Security and Compliance Notes

The repository contains real security controls, but several surfaces are intentionally permissive until explicitly hardened.

Important examples:

- OIDC support exists, but `auth.mode` defaults to `off`
- discovery, update, loader gossip, and Prometheus follower forwarding use symmetric shared-key MACs rather than asymmetric signatures
- the loader transfer server and status server are plain HTTP unless you add TLS externally
- `/metrics` is not OIDC-gated and should be protected with network controls or a reverse proxy
- `TraceyBan` action hooks run shell commands from configuration and may require root access

Detailed guidance is in `[SECURITY.md](SECURITY.md)`. Compliance posture notes are in `[COMPLIANCE.md](COMPLIANCE.md)`.

## Documentation Map

- `[WORKFLOW_ANALYSIS.md](WORKFLOW_ANALYSIS.md)`: detailed architecture, workflows, subsystem interactions, and current caveats
- `[docs/CONFIGURATION_REFERENCE.md](docs/CONFIGURATION_REFERENCE.md)`: configuration sections, defaults, sanitisation behaviour, and key override patterns
- `[docs/OPERATIONS.md](docs/OPERATIONS.md)`: commands, files, interfaces, service installation, and day-two operations
- `[SECURITY.md](SECURITY.md)`: security model, implemented controls, and hardening guidance
- `[COMPLIANCE.md](COMPLIANCE.md)`: compliance-support mapping and evidence considerations

## Local Verification

Last locally verified on **8 April 2026**:

```bash
cargo test
cargo run --locked --bin tracey -- --help
cargo run --locked --bin tracey -- tracey-ban actions
cargo run --locked --bin tracey -- tracey-guard --help
cargo run --locked --bin tracey -- --tui --help
cargo run --locked --bin tracey-top -- --help
```

Result: **171 tests passed, 0 failed**. The dashboard help commands still matched the documented three-page interface and the operator CLI help/catalog commands matched the documented `tracey-ban` and `tracey-guard` surfaces.
