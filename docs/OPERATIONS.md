# Operations Guide

This guide documents how the current codebase operates in practice as of **8 April 2026**. It is intended for engineers running Tracey locally, under supervisor mode, or through the separate `tracey-loader` service model.

## Runtime Modes

The repository exposes three runtime modes plus an attach-only operator dashboard.

### 1. Main runtime: `tracey`

Use this when you want the normal asynchronous runtime without the external loader.

```bash
cargo run
cargo run -- --version
```

Behaviour:

- loads `Config::load()`
- starts the swarm core, storage, governance, coordination, and agents
- starts default synthetic sensors unconditionally
- starts embedded collectors on supported systems
- starts optional subsystems according to config
- writes hand-off readiness when launched by supervisor or loader
- `--version` reports the runtime build version as `major.minor.build`; local source builds derive `build` from the git commit count so it increments on each commit

### 2. Supervisor mode: `tracey --supervisor`

Use this when you want the main binary to supervise and hand over to updated binaries without the separate loader service.

```bash
cargo run -- --supervisor
```

Behaviour:

- the wrapper process respawns the child if it exits
- update requests are read from `update.update_dir/tracey.supervisor.request.json`
- zero-downtime promotion waits for the new child to write the expected hand-off token before the old child is shut down
- the child receives `TRACEY_SUPERVISED=1` plus shutdown and hand-off token paths in its environment

### 3. Loader mode: `tracey-loader`

Use this for the long-lived mutable-core model.

```bash
cargo run --bin tracey-loader
cargo run --bin tracey-loader -- --version
```

Behaviour:

- verifies its own loader integrity manifest
- supervises a mutable Tracey core under `loader.state_dir`
- can promote locally staged updates handed to it by the core runtime
- can synchronise newer production cores from peers
- maintains rollback state during a probation window before redistributing the new core
- records suspicious provider and artifact incidents into loader-threat state and exposes the current summary via `/loader/status`

### 4. Operator dashboard: `tracey --tui` / `tracey-top`

Use this when you want an attach-only dashboard over the status surface and JSONL activity log.

```bash
cargo run -- --tui
cargo run -- --tui --help
cargo run --bin tracey-top -- --help
```

Behaviour:

- `tracey --tui` and `tracey-top` expose the same dashboard interface
- page 1 is the overview, page 2 is locations, and page 3 is Continuum telemetry
- current options are `--status`, `--bearer`, `--log-path` or `--no-log`, `--refresh-ms`, and `--tail-bytes`
- when `--status` is omitted, the dashboard prefers a reachable local agent instead of starting duplicate collectors
- the minimum supported terminal size is `120x33`

## Operator CLI

Use this when you want status and control access without hand-writing `curl` requests.

```bash
cargo run -- status
TRACEY_STATUS_ADDR=http://127.0.0.1:48000 cargo run -- tracey-ban status
cargo run -- tracey-ban filters
cargo run -- tracey-ban actions
cargo run -- tracey-ban ban --jail sshd-auth --ip 198.51.100.42 --reason manual
cargo run -- tracey-ban unban --jail sshd-auth --ip 198.51.100.42 --reason cleared
cargo run -- tracey-ban refresh-backend --jail sshd-auth
cargo run -- tracey-guard status
cargo run -- tracey-guard enable
cargo run -- tracey-guard deep-dive on
cargo run -- tracey-guard tmr off
cargo run -- tracey-guard set-overhead --pct 7.5
cargo run -- tracey-guard set-parallelism --count 8
cargo run -- tracey-guard force-scan
```

Operational notes:

- `tracey status` reads `/status`
- `tracey tracey-ban status|ban|unban|refresh-backend` read or write `/tracey_ban` and `/control/tracey_ban`
- `tracey tracey-ban filters|actions` print the built-in filter and action catalogs without contacting the API
- `tracey tracey-guard status` reads `/tracey_guard`
- `tracey tracey-guard enable|disable|deep-dive|tmr|set-overhead|set-parallelism|force-scan` write `/control/tracey_guard`
- `--addr`, `TRACEY_STATUS_ADDR`, `status.public_addr`, and `status.listen_addr` are resolved in that order
- `--token`, `TRACEY_STATUS_TOKEN`, and `TRACEY_AUTH_BEARER` all provide the bearer token
- local no-scheme targets default to `http://`; non-local no-scheme targets default to `https://`
- listener binds such as `0.0.0.0:48000` and `[::]:48000` are rewritten to loopback for local operator use
- add `--json` to print the raw API payload

## Update Signing Command

The main binary also provides an update-signing helper.

```bash
cargo run -- sign-update --bundle ./tracey-new --version 0.2.0 --key '<shared-key>'
```

Supported usage from the code:

```text
tracey sign-update --bundle <path> --version <v> [--os <os>] [--arch <arch>] [--channel production|development] [--out <dir>] [--key <key>]
```

Notes:

- `--key` may be omitted if `TRACEY_UPDATE_KEY` is set
- output defaults to `updates/tracey.update`, `updates/tracey.update.meta.json`, and `updates/tracey.update.sig`
- the generated "signature" is a keyed BLAKE3 MAC, not an asymmetric detached signature

## Startup Sequence

The main runtime in `src/lib.rs` starts in a fixed order.

1. Parse the CLI for `sign-update`, `--version`, and `--supervisor`.
2. Load config from defaults, optional JSON, environment overrides, and sanitisation.
3. Optionally re-exec via `sudo` if TraceyBan requires elevated access.
4. Build shutdown, storage, inventory, governance state, coordination, auth, Slurm, and loader-threat handles plus the swarm channels.
5. Start coordination election, the coordinator, Prometheus export, Continuum telemetry, Continuum assessment, Continuum autoscaler, swarm agents, and the status server.
6. Start the remaining producers and side runtimes: stimuli, telemetry ingest, synthetic sensors, embedded collectors, TraceyBan, discovery, asset feed, Refiner tracking, and the update manager.
7. Signal hand-off readiness if a parent process requested it.

Operational consequence: the decision-making core is always started before most producers and side subsystems.

## Default Network Surfaces

| Surface | Default bind | Purpose | Security note |
| --- | --- | --- | --- |
| Status API | `0.0.0.0:48000` | Status, health, readiness, location, TraceyBan, TraceyGuard, Continuum surfaces, `/metrics`, `/prometheus/ingest` | Open by default unless OIDC is enabled; `/metrics` is always unauthenticated in-process. |
| Discovery gossip | `0.0.0.0:47990` | Peer presence, capability, ban, fault, Slurm, and Prometheus-probe gossip | Shared-key authenticated, not encrypted. |
| Loader gossip | `0.0.0.0:47989` | Loader peer announcements | Shared-key authenticated, not encrypted. |
| Loader transfer | `0.0.0.0:47988` | Loader health, status, metadata, signature, and bundle distribution | Plain HTTP; integrity is checked after download. |
| OTLP gRPC | `127.0.0.1:4317` | OTLP metrics ingest | Disabled by default. |
| OTLP HTTP | `127.0.0.1:4318` | OTLP metrics ingest | Disabled by default. |
| Stimuli bridge | `0.0.0.0:48100` | UDP AER ingress and egress | Disabled by default. |

## HTTP Routes

### Main status server

When `status.enabled` is true, the Axum server exposes:

- `GET /status`
- `GET /health`
- `GET /ready`
- `GET /tracey_ban`
- `POST /control/tracey_ban`
- `GET /tracey_guard`
- `GET /tracey_guard/deepdive`
- `POST /control/tracey_guard`
- `GET /metrics`
- `POST /prometheus/ingest`

Important operational notes:

- `/status`, `/health`, and `/ready` all return the same status snapshot shape
- followers may proxy `/status` to the elected proxy node
- `/tracey_ban` returns TraceyBan jail state, active bans, and remote ban intelligence
- `/tracey_guard/deepdive` currently returns the same snapshot shape as `/tracey_guard`
- `/control/tracey_ban` and `/control/tracey_guard` are the endpoints used by the operator CLI
- `/metrics` does not pass through OIDC route protection
- `/prometheus/ingest` is authenticated by a shared-key request MAC rather than OIDC
- the status snapshot includes posture and coordination plus optional Slurm, Continuum autoscaler/assessment/telemetry, loader-threat, and inferred location snapshots

### Loader transfer server

When `tracey-loader` is running, the transfer server exposes:

- `GET /health`
- `GET /loader/status`
- `GET /loader/core/metadata`
- `GET /loader/core/signature`
- `GET /loader/core/bundle`

Important operational notes:

- `/loader/status` returns the current core version/channel, distributable state, pending rollback state, and the current loader-threat snapshot
- bundle-serving routes return `404` unless the local core is distributable
- a core is distributable only when both the loader policy channel and the current core channel are production, and there is no pending rollback probation

## Working Directory and Relative Paths

The runtime uses relative paths extensively. That makes the process working directory part of the deployment contract.

Examples:

- `tracey.log.jsonl`
- `updates/`
- `loader/`
- `tracey.tracey_ban.state.json`
- `asset_feed.jsonl`
- `refiner_security_feed.jsonl`

The systemd installer deliberately sets `WorkingDirectory` to the chosen state directory. In a system install, that is `/var/lib/tracey` by default. As a result, the generated default config yields a layout like:

- `/var/lib/tracey/tracey.log.jsonl`
- `/var/lib/tracey/updates/`
- `/var/lib/tracey/loader/`

If you launch binaries manually from the repository root instead, the same relative paths land in the repository directory.

## Runtime File Layout

### Main runtime storage

By default the main runtime writes:

- `tracey.log.jsonl`
- optional archives such as `tracey.log.jsonl.1`, `tracey.log.jsonl.2`, and `tracey.log.jsonl.3`

The file contains JSONL records for events, decisions, learning snapshots, governance updates, update records, ban updates, inventory records, tuning updates, and compaction summaries.

### Update directory

When the built-in update manager is enabled, it works from `update.update_dir`, which defaults to `updates`.

Important files include:

- `tracey.update`
- `tracey.update.meta.json`
- `tracey.update.sig`
- `tracey.next` after staging
- `tracey.applied.<timestamp>` plus matching `.meta.json` and `.sig` archives after successful application
- `tracey.supervisor.request.json` when a supervised or loader-managed update is handed off for promotion
- `handoff-<token>.ready` and `shutdown-<token>.token` during process coordination

### Loader state tree

The loader state root defaults to `loader` under the current working directory.

Important files and directories include:

- `loader/current/tracey-core`
- `loader/current/tracey-core.meta.json`
- `loader/current/tracey-core.sig`
- `loader/rollback/tracey-core.previous`
- `loader/rollback/tracey-core.previous.meta.json`
- `loader/rollback/tracey-core.previous.sig`
- `loader/tracey-loader.rollback.json`
- `loader/tracey-loader.manifest.json`
- `loader/tracey-loader.threats.state.json`
- `loader/tracey-loader.threats.snapshot.json`
- `loader/staging/`

Operational meaning:

- `current/` is the active mutable core
- `rollback/` stores the previous verified core during a probation window
- `tracey-loader.rollback.json` records the current probation state
- `tracey-loader.manifest.json` records the loader binary digest and last verification timestamp
- `tracey-loader.threats.state.json` stores persisted local loader-threat incidents
- `tracey-loader.threats.snapshot.json` stores the latest loader-threat snapshot used by `/loader/status` and the main `/status` surface
- `staging/` is used for fetched peer cores and archived failed promotions

### TraceyBan state

When TraceyBan is enabled, `tracey_ban.state_path` stores:

- per-log offsets
- persisted active bans
- ban counters

That file is separate from the main JSONL storage stream.

## Local Development Workflow

For direct repository runs:

```bash
cargo run
cargo test --all-targets
```

Current verified result on **7 April 2026**:

- `cargo test --all-targets` passed with `145 passed, 0 failed`
- `cargo run --locked --bin tracey -- --tui --help` printed the current three-page dashboard help
- `cargo run --locked --bin tracey-top -- --help` matched the same interface

Practical expectations for an unconfigured run:

- synthetic events begin immediately
- embedded collectors and TraceyGuard are active
- discovery and status surfaces are active
- status binds to `0.0.0.0:48000`
- Continuum telemetry and inferred location snapshots are available on `/status` and in the dashboard even before any external Continuum service is configured
- Continuum assessment and Continuum autoscaler remain disabled until a Continuum base URL is configured
- Prometheus pertinent-log export begins probing `https://prometheus.neuralmimicry.ai/-/ready`

## Loader Bootstrap Workflow

A new loader deployment needs a core binary at `loader/current/tracey-core` relative to `loader.state_dir`.

Minimal manual bootstrap example:

```bash
mkdir -p ./state/loader/current
cp ./target/release/tracey ./state/loader/current/tracey-core
TRACEY_CONFIG=./tracey.json cargo run --bin tracey-loader
```

A suitable `tracey.json` would need at least:

```json
{
  "agent_id": "tracey-node-01",
  "update": {
    "local_channel": "production",
    "shared_key": "replace-this-key"
  },
  "discovery": {
    "shared_key": "replace-this-key"
  },
  "loader": {
    "enabled": true,
    "state_dir": "./state/loader"
  }
}
```

Bootstrap behaviour from the current code:

- if the core binary exists and the metadata/signature files already exist, the loader verifies them and proceeds
- if the core binary exists but metadata and signature are missing, the loader generates them locally using the configured artefact key
- the version used for that generated metadata comes from `tracey-core --version` when possible, otherwise from `loader.bootstrap_version`, otherwise from the package version
- in practice `tracey-core --version` is the preferred path and returns the git-aware runtime build version for source builds
- if there is no core binary at all, the loader exits with an error

## Staged Update Workflow

### Main runtime without supervisor

1. Place `tracey.update`, `tracey.update.meta.json`, and `tracey.update.sig` in `update.update_dir`.
2. Ensure `update.enabled=true` and `update.shared_key` is set.
3. The runtime verifies the artefacts.
4. If OS, architecture, and channel match, it stages `tracey.next`, launches the new binary, waits for hand-off readiness, records `update_record`, and then shuts the old process down.

### Main runtime with `--supervisor`

1. Stage the same three artefacts.
2. The child runtime verifies and stages the binary.
3. Instead of replacing itself directly, it writes `tracey.supervisor.request.json`.
4. The supervisor performs the hand-off and keeps watching the new child.

### Loader-managed runtime

1. Run `tracey-loader` as the service entry point.
2. The managed core may still verify staged update artefacts itself.
3. When supervised inside the loader, the core writes a supervisor request into `update.update_dir`.
4. The loader verifies that request, snapshots the previous core, performs hand-off to the staged binary, promotes the new core into `loader/current/`, and starts rollback probation.
5. If the promoted core exits during probation, the loader restores the previous verified core automatically.

## Peer Synchronisation Workflow

When running `tracey-loader` on a production channel:

1. the loader announces the current core version, digest, channel, and transfer address over UDP gossip
2. peers collect those announcements and choose the highest newer production version within TTL
3. the selected peer’s metadata, signature, and bundle are fetched over HTTP
4. the fetched artefacts are verified locally with the configured artefact key
5. the new core is handed over and promoted locally
6. redistribution is withheld until the rollback window expires

Important caveats:

- loader sync only considers production-channel cores for redistribution
- plain HTTP is used for transfer unless you add TLS externally
- the peer announcement and the fetched artefacts must agree on version and digest, or the sync attempt is rejected

## Remote Update Fetch Workflow

The built-in update manager can also fetch staged artefacts from a remote server.

Required settings:

- `update.remote.enabled=true`
- `update.remote.base_url`
- `update.remote.ca_cert_path`
- `update.remote.client_identity_path`

Current behaviour:

- Tracey builds a `reqwest` client with the supplied CA certificate and client identity
- metadata, bundle, and signature are fetched independently
- the fetched files are written into `update.update_dir`
- normal local verification then decides whether the update is ignored, rejected, staged, or applied

Operational limitation: the repository expects PEM material on disk and does not provide an opinionated secret-management path around it.

## Service Installation Script

`scripts/install-service.sh` installs Tracey under `systemd` on Linux.

### Scope behaviour

- `--scope auto` resolves to `system`
- `--scope user` is explicit opt-in
- system scope uses `sudo` when needed
- user scope requires a working user `systemd` session

### Binary selection

Unless explicit binary paths are supplied, the script tries in this order:

- repository `target/release/`
- repository `target/debug/`
- binaries found on `PATH`

If a required release binary is missing and Cargo is available, the script may build `tracey` and `tracey-loader` automatically.

### Default paths

System scope defaults:

- loader binary: `/usr/local/bin/tracey-loader`
- config: `/etc/tracey/tracey.json`
- state directory: `/var/lib/tracey`
- unit file: `/etc/systemd/system/tracey.service`
- environment file: `/etc/default/tracey`

User scope defaults:

- loader binary: `$HOME/.local/bin/tracey-loader`
- config: `$XDG_CONFIG_HOME/tracey/tracey.json`
- state directory: `$XDG_STATE_HOME/tracey`
- unit file: `$XDG_CONFIG_HOME/systemd/user/tracey.service`
- environment file: `$XDG_CONFIG_HOME/tracey/tracey.env`

### Generated config

By default the installer writes a minimal JSON config containing:

- `agent_id`
- `storage.log_path = "tracey.log.jsonl"`
- `update.update_dir = "updates"`
- `update.local_channel`
- `loader.enabled = true`
- `loader.state_dir = "loader"`
- optional `loader.bootstrap_version`
- `prometheus_log_export.server_url = "http://prometheus.neuralmimicry.ai"`

The generated config relies on the built-in default status surface of `0.0.0.0:48000` unless an existing config is being preserved.

That installer-generated Prometheus URL intentionally overrides the compiled `https://` default unless you preserve or replace the config.

It does **not** write discovery or update shared keys automatically.

### Generated environment file

The installer creates an optional environment file scaffold containing commented examples such as:

- `TRACEY_DISCOVERY_SHARED_KEY=rotate-this-key`
- `TRACEY_UPDATE_SHARED_KEY=rotate-this-key`
- `TRACEY_UPDATE_LOCAL_CHANNEL=development`

### Generated unit

The generated service unit currently includes:

- `Environment=TRACEY_CONFIG=<config-path>`
- `EnvironmentFile=-<env-file>`
- `WorkingDirectory=<state-dir>`
- `ExecStart=<loader-binary>`
- `Restart=always`
- `RestartSec=2`
- `LimitNOFILE=65536`
- `NoNewPrivileges=true`

### Scope conflict handling

The installer also manages common scope conflicts:

- when installing a system service, it disables a conflicting user service of the same name if one is active or enabled
- when installing a user service, it refuses to proceed if a system service of the same name is already active or enabled
- in user scope, it warns if `loginctl enable-linger` is not set for the user

### Firewall handling

The installer derives the effective `status.listen_addr` before writing or reusing the service config.

- if the status API is disabled or bound only to loopback, it does not change the firewall
- if the status API binds to a non-loopback address, it checks `ufw` first and then `firewalld`
- when a supported firewall is active and the installer has privileges, it opens `tcp/<status-port>` so the status API remains reachable
- when a supported firewall is active but the installer is unprivileged, or when `nftables` is active without a supported front-end, it warns and reports the exact manual port to allow

## Hardening Checklist

A minimal production hardening pass should normally include all of the following.

1. Rotate `discovery.shared_key` and `update.shared_key`, or disable those subsystems entirely.
2. Move `status.listen_addr` to loopback or place the service behind a trusted reverse proxy or service mesh.
3. Enable OIDC if any status or OTLP surface is reachable by untrusted clients.
4. Decide whether synthetic sensors and TraceyGuard synthetic fallback are acceptable in the target environment.
5. Disable Prometheus pertinent-log export if probing `https://prometheus.neuralmimicry.ai/-/ready` is not desired, or `http://prometheus.neuralmimicry.ai/-/ready` when using the installer-generated config.
6. Review all TraceyBan action hooks as privileged code before enabling them.
7. Restrict loader transfer reachability and add external TLS if bundle confidentiality matters.
8. Review relative-path behaviour so logs, updates, loader state, and TraceyBan state land in the intended directory tree.

## Common Failure Modes

### Status server does not start

Likely causes:

- `status.listen_addr` is invalid
- another process already holds the port
- the route was disabled because `status.listen_addr` was blank

### Discovery appears silent

Likely causes:

- `discovery.shared_key` is blank, which disables discovery during sanitisation
- local broadcast is filtered on the network
- peers are on a different segment

### Loader refuses to start

Likely causes:

- `loader.enabled` is false
- neither `update.shared_key` nor `discovery.shared_key` is configured
- `loader/current/tracey-core` is missing
- the existing core metadata or signature does not verify against the current artefact key

### Updates are ignored or rejected

Likely causes:

- channel mismatch between staged metadata and `update.local_channel`
- OS or architecture mismatch
- invalid keyed digest
- governance posture has disabled updates

### TraceyBan elevates or fails unexpectedly

Likely causes:

- configured jails reference protected log locations under `/var/log` or similar
- an action command contains firewall tooling and therefore triggers privileged execution logic
- the sudo path or privileges are not available
