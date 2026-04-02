# Configuration Reference

This reference describes the configuration model implemented in the repository as of **31 March 2026**. It is based on `src/config.rs` and the runtime wiring in `src/lib.rs`, `src/update.rs`, `src/loader.rs`, `src/status.rs`, and related modules.

## Loading Order

Configuration is loaded in this order:

`defaults < JSON from TRACEY_CONFIG < supported environment overrides < sanitisation`

Practical implications:

- if `TRACEY_CONFIG` is unset, Tracey runs entirely from compiled defaults plus any recognised environment overrides
- the JSON file may omit any field because the config structs use `serde(default)`
- environment overrides are selective rather than exhaustive; they cover the most operationally significant knobs, not every field in the schema
- sanitisation is always the final step, so out-of-range values are clamped and some invalid subsystem combinations are disabled automatically

## Path Resolution

Many filesystem settings are relative paths by default, for example:

- `storage.log_path = "tracey.log.jsonl"`
- `update.update_dir = "updates"`
- `loader.state_dir = "loader"`
- `tracey_ban.state_path = "tracey.tracey_ban.state.json"`
- `asset_feed.path = "asset_feed.jsonl"`
- `refiner.security_feed_path = "refiner_security_feed.jsonl"`

The code uses those paths relative to the process working directory. This matters operationally because the service installer sets `WorkingDirectory` to the Tracey state directory, so relative paths land inside the service state tree rather than the repository root.

## Effective Default Profile

A plain `cargo run` or `tracey` launch with no config file currently results in all of the following:

- six swarm agents
- assessment quorum of four
- decision threshold of `0.75`
- active response disabled
- shutdown decisions disabled
- synthetic sensors enabled
- embedded collectors enabled
- TraceyGuard enabled
- discovery enabled on UDP `47990`
- status enabled on `0.0.0.0:48000`
- OIDC support present but disabled
- Prometheus pertinent-log export enabled
- telemetry ingest disabled
- TraceyBan disabled
- asset feed disabled
- Refiner tracking disabled
- update manager disabled
- stimuli/AER bridge disabled
- loader configuration present and enabled for the separate `tracey-loader` binary

That profile is suitable for experimentation and self-exercise, not for a hardened deployment.

## Core Runtime Settings

| Field | Default | Meaning |
| --- | --- | --- |
| `agent_id` | host name plus PID | Local node identifier used across discovery, status, and loader workflows. |
| `agents` | `6` | Number of swarm scoring agents created in-process. |
| `bus_capacity` | `2048` | Broadcast event-bus depth. |
| `assessment_channel_capacity` | `2048` | Capacity for assessment, governance, and decision channels. |
| `assessment_quorum` | `4` | Number of agent assessments required for normal coordinator finalisation. |
| `decision_threshold` | `0.75` | Base risk threshold used by the coordinator before posture adjustments. |
| `decision_ttl_ms` | `1500` | Time window before a pending decision is finalised on expiry rather than quorum. |
| `event_rate_ms` | `150` | Tick interval for the synthetic sensors. |
| `learning_merge_alpha` | `0.15` | Learning-snapshot merge factor used by agents. |
| `learning_broadcast_ms` | `2000` | Coordinator learning broadcast interval. |
| `directive_broadcast_ms` | `2500` | Coordinator directive broadcast interval. |
| `min_samples` | `12` | Minimum observations before learned-confidence scaling reaches maturity. |
| `active_response` | `false` | Whether coordinator actions above alert level may become active responses. Governance can still suppress them. |
| `shutdown_enabled` | `false` | Whether shutdown is ever allowed as a final action. Governance only enables it in lockdown posture when this base flag is already true. |

### Action policy defaults

`policy` controls how risk and confidence map to actions.

| Field | Default |
| --- | --- |
| `policy.alert_threshold` | `0.65` |
| `policy.throttle_threshold` | `0.78` |
| `policy.isolate_threshold` | `0.88` |
| `policy.shutdown_threshold` | `0.97` |
| `policy.min_confidence` | `0.55` |

## Fuzzy Scoring

Global fuzzy scoring is enabled by default.

| Field | Default | Notes |
| --- | --- | --- |
| `fuzzy.enabled` | `true` | Turns Type-n fuzzy refinement on or off. |
| `fuzzy.order` | `3` | Recursion depth for interval refinement. |
| `fuzzy.uncertainty` | `0.55` | Base uncertainty contribution. |
| `fuzzy.edge_bias` | `0.70` | Weight applied to edge/novelty membership. |
| `fuzzy.aarnn_weight` | `0.22` | Additional context weight for AARNN-related events. |
| `fuzzy.security_weight` | `0.28` | Additional context weight for security-oriented events. |

## Storage

| Field | Default | Notes |
| --- | --- | --- |
| `storage.log_path` | `tracey.log.jsonl` | Primary JSONL record file. |
| `storage.max_bytes` | `25_000_000` | Active file rotation or compaction threshold. |
| `storage.max_total_bytes` | `100_000_000` | Combined active plus archive budget. |
| `storage.retain_lines` | `5000` | Lines retained when in-place compaction is used. |
| `storage.compact_interval_ms` | `30_000` | Housekeeping interval. |
| `storage.rotate_archives` | `3` | Number of numbered archives retained when rotation is enabled. |
| `storage.summary_top_keys` | `25` | Number of keys preserved in compaction summaries. |

Operational notes:

- when `rotate_archives > 0`, oversize logs are rotated to `tracey.log.jsonl.1`, `.2`, and so on
- when `rotate_archives = 0`, in-place compaction writes a `log_summary` record and keeps the newest `retain_lines`
- if `max_total_bytes < max_bytes`, sanitisation raises `max_total_bytes` to match `max_bytes`

## Discovery and Inventory

### Discovery

| Field | Default | Notes |
| --- | --- | --- |
| `discovery.enabled` | `true` | Enables broadcast peer gossip. |
| `discovery.bind_addr` | `0.0.0.0:47990` | Local UDP bind address. |
| `discovery.broadcast_addr` | `255.255.255.255:47990` | Broadcast destination. |
| `discovery.advertise_addr` | `null` | Optional explicit address advertised to peers. |
| `discovery.shared_key` | `tracey-dev-key-change-me` | Shared secret used for MAC validation. |
| `discovery.announce_interval_ms` | `1500` | Gossip interval. |
| `discovery.ttl_ms` | `10_000` | Peer-entry validity period. |

Important behaviour:

- if `discovery.shared_key` is blank after overrides, sanitisation disables discovery entirely
- the code warns if the default development key is still in use
- discovery gossip is authenticated but not encrypted

### Inventory

| Field | Default | Notes |
| --- | --- | --- |
| `inventory.agent_ttl_ms` | `30_000` | Retention of discovered agent presence. |
| `inventory.host_ttl_ms` | `120_000` | Retention of observed host records. |
| `inventory.unmanaged_resend_ms` | `30_000` | How often unmanaged-host records may be re-emitted. |

## Asset Feed and Refiner Tracking

### Asset feed

| Field | Default | Notes |
| --- | --- | --- |
| `asset_feed.enabled` | `false` | Enables JSONL host-observation ingestion. |
| `asset_feed.path` | `asset_feed.jsonl` | File polled for host observations. |
| `asset_feed.poll_interval_ms` | `3000` | Poll interval. |
| `asset_feed.source` | `asset_feed` | Source label recorded with observations. |

### Refiner tracking

| Field | Default | Notes |
| --- | --- | --- |
| `refiner.enabled` | `false` | Enables Refiner health and finding ingestion. |
| `refiner.source` | `refiner` | Event source label. |
| `refiner.service_name` | `refiner` | Service identifier included in events. |
| `refiner.health_url` | `http://127.0.0.1:5001/api/health` | HTTP health probe target. |
| `refiner.security_feed_path` | `refiner_security_feed.jsonl` | JSONL findings feed. |
| `refiner.poll_interval_ms` | `5000` | Poll interval. |
| `refiner.timeout_ms` | `2500` | Health-check timeout. |

Important behaviour:

- if `refiner.health_url` is blank after overrides, sanitisation disables the Refiner subsystem

## Telemetry Ingest

### Prometheus and generic telemetry settings

| Field | Default | Notes |
| --- | --- | --- |
| `telemetry.enabled` | `false` | Master switch for telemetry ingest. |
| `telemetry.prometheus_enabled` | `true` | Allows Prometheus scraping once telemetry is enabled. |
| `telemetry.endpoints` | `[]` | Additional scrape targets. |
| `telemetry.scrape_interval_ms` | `5000` | Scrape interval. |
| `telemetry.max_samples` | `200` | Maximum emitted metrics per scrape or ingest request. |
| `telemetry.allow_prefixes` | predefined list | Permitted metric-name prefixes such as `process_`, `system_`, `node_`, `cpu`, `mem`, `load`, `http_`, and `otelcol_`. |
| `telemetry.allow_exact` | `[]` | Additional exact metric-name allow-list entries. |
| `telemetry.autodiscover_local` | `true` | Adds fixed loopback scrape targets automatically. |
| `telemetry.allow_remote` | `false` | Permits non-loopback scrape targets only when governance also allows remote telemetry. |
| `telemetry.source` | `telemetry` | Source label for emitted events. |
| `telemetry.timeout_ms` | `2000` | HTTP timeout for scrapes. |
| `telemetry.prefer_prometheus` | `true` | Suppresses duplicate OTLP values when a recent Prometheus sample exists. |
| `telemetry.dedup_ttl_ms` | `30_000` | Prometheus preference TTL. |

When `autodiscover_local` is enabled, Tracey adds these loopback scrape targets:

- `http://127.0.0.1:8888/metrics`
- `http://127.0.0.1:8889/metrics`
- `http://127.0.0.1:9100/metrics`
- `http://127.0.0.1:9464/metrics`

`TRACEY_TELEMETRY_ENDPOINTS`, `PROMETHEUS_ENDPOINT`, `PROMETHEUS_URL`, and `OTEL_PROMETHEUS_ENDPOINT` can also add scrape targets at runtime.

### OTLP receiver settings

| Field | Default | Notes |
| --- | --- | --- |
| `telemetry.otlp.enabled` | `false` | Enables OTLP receiver startup. |
| `telemetry.otlp.grpc_addr` | `127.0.0.1:4317` | OTLP gRPC bind address. |
| `telemetry.otlp.http_addr` | `127.0.0.1:4318` | OTLP HTTP bind address. |
| `telemetry.otlp.enable_grpc` | `true` | Starts the gRPC receiver when OTLP is enabled. |
| `telemetry.otlp.enable_http` | `true` | Starts the HTTP receiver when OTLP is enabled. |

Important behaviour:

- OTLP route protection only matters when `auth.mode=oidc`
- invalid OTLP bind addresses are not sanitised away centrally; the affected listener simply fails to bind at runtime

## Prometheus Pertinent-Log Export

| Field | Default | Notes |
| --- | --- | --- |
| `prometheus_log_export.enabled` | `true` | Enables the exporter runtime when status is enabled. |
| `prometheus_log_export.server_url` | `http://prometheus.neuralmimicry.ai` | External Prometheus instance probed for readiness. |
| `prometheus_log_export.probe_path` | `/-/ready` | Readiness path appended to `server_url`. |
| `prometheus_log_export.probe_interval_ms` | `5000` | Probe cadence. |
| `prometheus_log_export.probe_timeout_ms` | `1500` | Probe timeout. |
| `prometheus_log_export.forward_interval_ms` | `1000` | Follower forwarding cadence. |
| `prometheus_log_export.batch_ttl_ms` | `30_000` | Maximum accepted batch age. |
| `prometheus_log_export.max_batch` | `64` | Maximum forwarded records per batch. |
| `prometheus_log_export.max_queue` | `2048` | Pending pertinent-record queue depth. |
| `prometheus_log_export.min_signal` | `0.70` | Event signal floor for most exported event categories. |
| `prometheus_log_export.min_decision_risk` | `0.70` | Decision risk floor. |
| `prometheus_log_export.series_ttl_ms` | `86_400_000` | Series retention window. |

Important behaviour:

- if `prometheus_log_export.server_url` is blank, sanitisation disables the exporter
- if `status.enabled` is false, sanitisation also disables the exporter
- `/metrics` is exposed without OIDC gating; `/prometheus/ingest` uses a shared-key MAC instead

## Embedded Collectors

| Field | Default | Notes |
| --- | --- | --- |
| `embedded.enabled` | `true` | Enables embedded collectors. |
| `embedded.interval_ms` | `2000` | Collection cadence. |
| `embedded.jetson_enabled` | `true` | Enables Jetson-specific collectors where relevant. |
| `embedded.max_thermals` | `8` | Maximum thermal sensors recorded per cycle. |
| `embedded.max_disks` | `8` | Maximum disk devices recorded per cycle. |
| `embedded.max_interfaces` | `8` | Maximum network interfaces recorded per cycle. |
| `embedded.process_enabled` | `true` | Enables top-process summaries. |
| `embedded.process_top_n` | `5` | Number of processes surfaced. |
| `embedded.process_window_ms` | `5000` | Process window duration. |
| `embedded.process_max` | `2048` | Process scan cap. |
| `embedded.gpu_enabled` | `true` | Enables GPU telemetry collection. |
| `embedded.gpu_sysfs_enabled` | `true` | Enables Linux sysfs GPU probing. |
| `embedded.gpu_nvml_enabled` | `true` | Enables NVML probing where available. |
| `embedded.gpu_rocm_enabled` | `true` | Enables ROCm probing where available. |
| `embedded.gpu_max_devices` | `8` | Maximum GPUs enumerated by embedded collectors. |

## TraceyGuard

TraceyGuard is enabled by default.

### Top-level settings

| Field | Default | Notes |
| --- | --- | --- |
| `tracey_guard.enabled` | `true` | Enables the TraceyGuard runtime. |
| `tracey_guard.scheduler_poll_ms` | `200` | Minimum probe scheduler loop cadence; the runtime stretches above this when fleet risk is low and converges back toward it as risk rises. |
| `tracey_guard.max_parallel_tasks` | `32` | Concurrent probe-task limit. |
| `tracey_guard.overhead_budget_pct` | `2.0` | Intended runtime overhead budget. |
| `tracey_guard.max_devices` | `32` | Maximum devices tracked. |
| `tracey_guard.synthetic_devices` | `1` | Synthetic devices created when no real GPUs are available. |
| `tracey_guard.default_sm_count` | `16` | Default SM count for synthetic devices. |
| `tracey_guard.max_advertised_faults` | `64` | Maximum faults advertised over discovery. |
| `tracey_guard.remote_fault_ttl_ms` | `120_000` | Remote fault-intel retention. |
| `tracey_guard.deep_dive_max_faults` | `256` | Snapshot cap for deeper fault detail. |

The TraceyGuard scheduler now derives its effective poll interval from recent probe outcomes, device lifecycle state, fuzzy risk, telemetry stress, deep-dive mode, and budget pressure. Low-risk healthy fleets drift toward less frequent polling; suspect, quarantined, or fault-active fleets tighten polling and shorten effective probe periods with a gradual recovery back to lower overhead once risk subsides.

Even when the main cadence stretches out, TraceyGuard also injects lightweight random audit probes at irregular times so quiet windows do not become fully predictable. Those audits are biased toward cheaper, higher-priority probes and stay bounded by the same overhead posture.

### TMR settings

| Field | Default |
| --- | --- |
| `tracey_guard.tmr.enabled` | `true` |
| `tracey_guard.tmr.interval_ms` | `600_000` |
| `tracey_guard.tmr.timeout_ms` | `30_000` |
| `tracey_guard.tmr.triples_per_interval` | `3` |

### Correlation settings

| Field | Default |
| --- | --- |
| `tracey_guard.correlation.window_ms` | `300_000` |
| `tracey_guard.correlation.min_confidence` | `0.6` |
| `tracey_guard.correlation.healthy_to_suspect` | `0.95` |
| `tracey_guard.correlation.suspect_to_quarantine` | `0.80` |
| `tracey_guard.correlation.quarantine_to_healthy` | `0.98` |
| `tracey_guard.correlation.immediate_quarantine_failures` | `3` |
| `tracey_guard.correlation.deep_test_passes` | `128` |

### Probe catalogue defaults

| Probe | Enabled | Period | SM coverage | Priority | Timeout |
| --- | --- | --- | --- | --- | --- |
| `fma` | `true` | `60_000` | `1.0` | `1` | `500` |
| `tensor_core` | `true` | `60_000` | `1.0` | `1` | `1_000` |
| `transcendental` | `true` | `120_000` | `0.5` | `2` | `500` |
| `aes` | `true` | `300_000` | `0.25` | `3` | `2_000` |
| `memory` | `true` | `600_000` | `1.0` | `4` | `5_000` |
| `register_file` | `true` | `120_000` | `1.0` | `2` | `500` |
| `shared_memory` | `true` | `300_000` | `0.5` | `3` | `1_000` |

Important behaviour:

- real GPU identity discovery is attempted where possible
- if no real devices are available, synthetic devices are created instead
- the current probe path is synthetic and CPU-side rather than executing real GPU kernels
- `TraceyGuardGpuState::Condemned` exists in the model, but the current transition logic does not automatically promote devices into it

## TraceyBan

TraceyBan is disabled by default but substantially configured out of the box.

### Top-level settings

| Field | Default | Notes |
| --- | --- | --- |
| `tracey_ban.enabled` | `false` | Enables the TraceyBan runtime. |
| `tracey_ban.state_path` | `tracey.tracey_ban.state.json` | Persisted offsets, active bans, and ban counters. |
| `tracey_ban.max_advertised_ips` | `64` | Maximum ban entries advertised to peers. |
| `tracey_ban.remote_ttl_ms` | `15_000` | Remote ban-intel retention. |
| `tracey_ban.unban_check_ms` | `1000` | Periodic unban check interval. |
| `tracey_ban.persist_interval_ms` | `3000` | State persistence interval. |
| `tracey_ban.agent_id` | empty by default | Filled from top-level `agent_id` during sanitisation if blank. |
| `tracey_ban.auto_elevate_root` | `true` | Allows pre-start self-elevation via `sudo` for protected log access or privileged actions. |
| `tracey_ban.sudo_program` | `sudo` | Sudo executable used for elevation or action wrapping. |
| `tracey_ban.sudo_non_interactive` | `true` | Uses non-interactive sudo mode where applicable. |
| `tracey_ban.use_sudo_for_actions` | `true` | Allows actions to be wrapped in sudo. |
| `tracey_ban.inherit_global_fuzzy` | `true` | Copies global fuzzy settings and `min_samples` at runtime. |
| `tracey_ban.min_samples` | `12` | Local value only used when inheritance is disabled. |
| `tracey_ban.fuzzy_min_risk` | `0.62` | Minimum fuzzy risk for ban confirmation. |
| `tracey_ban.fuzzy_min_confidence` | `0.30` | Minimum fuzzy confidence for ban confirmation. |
| `tracey_ban.fuzzy_retry_reduction` | `0.55` | Retry reduction factor when fuzzy scoring softens a decision. |

### Default jail

TraceyBan ships with one default enabled jail.

| Field | Default |
| --- | --- |
| `tracey_ban.jails[0].name` | `tracey-default` |
| `enabled` | `true` |
| `backend` | `tracey_event` |
| `max_retry` | `3` |
| `find_time_ms` | `600_000` |
| `ban_time_ms` | `600_000` |
| `ban_increment` | `true` |
| `ban_multiplier` | `2.0` |
| `ban_max_time_ms` | `7_200_000` |
| `ban_randomize_ms` | `15_000` |
| `ignore_ips` | `127.0.0.1`, `::1` |
| `poll_interval_ms` | `1000` |
| `shell` | `/bin/sh` |
| `action_timeout_ms` | `5000` |

Default event IP keys are:

- `ip`
- `src_ip`
- `source_ip`
- `client_ip`
- `remote_addr`

Important behaviour:

- if a jail name is blank, sanitisation replaces it with `tracey-jail-N`
- if a jail shell is blank, sanitisation restores `/bin/sh`
- if `event_ip_keys` is empty, sanitisation restores the default IP-key list
- TraceyBan action hooks are arbitrary shell commands and should be treated as privileged code

## Governance, Coordination, and Tuning

### Governance

| Field | Default |
| --- | --- |
| `governance.enabled` | `true` |
| `governance.vote_interval_ms` | `1500` |
| `governance.vote_ttl_ms` | `5000` |
| `governance.quorum` | `3` |
| `governance.decision_threshold` | `0.6` |
| `governance.min_confidence` | `0.5` |
| `governance.relaxed_risk` | `0.2` |
| `governance.strict_risk` | `0.7` |
| `governance.lockdown_risk` | `0.9` |
| `governance.rebel.enabled` | `false` |
| `governance.rebel.probability` | `0.03` |
| `governance.rebel.max_streak` | `2` |
| `governance.rebel.cooldown_ms` | `10_000` |

Important behaviour:

- governance posture adjusts the live decision threshold around the base threshold
- active response is only enabled in strict or lockdown posture when the base `active_response` flag is already true
- updates are disabled in strict and lockdown posture even if the update manager is otherwise enabled
- remote telemetry scraping is only allowed in relaxed posture and only when `telemetry.allow_remote` is also true

### Coordination

| Field | Default |
| --- | --- |
| `coordination.enabled` | `true` |
| `coordination.max_coordinators` | `2` |
| `coordination.election_interval_ms` | `1000` |
| `coordination.presence_ttl_ms` | `8000` |
| `coordination.weight_cpu` | `1.0` |
| `coordination.weight_latency` | `1.5` |
| `coordination.weight_hash` | `0.1` |
| `coordination.weight_capability` | `0.5` |
| `coordination.weight_prometheus_latency` | `2.5` |
| `coordination.weight_prometheus_bandwidth` | `1.2` |

### Adaptive tuning

| Field | Default |
| --- | --- |
| `tuning.enabled` | `false` |
| `tuning.target_alert_rate` | `0.08` |
| `tuning.adjustment_rate` | `0.05` |
| `tuning.min_threshold` | `0.55` |
| `tuning.max_threshold` | `0.95` |
| `tuning.window_ms` | `10_000` |

## Status API and Authentication

### Status

| Field | Default | Notes |
| --- | --- | --- |
| `status.enabled` | `true` | Enables the Axum status server. |
| `status.listen_addr` | `0.0.0.0:48000` | Local bind address. |
| `status.public_addr` | `null` | Optional externally advertised status address. |
| `status.proxy_timeout_ms` | `1500` | Timeout used when followers proxy to the elected status proxy. |

Important behaviour:

- if `status.listen_addr` is blank, sanitisation disables the status server
- when status is disabled, sanitisation also disables the Prometheus pertinent-log exporter
- invalid non-blank status addresses are not sanitised; the runtime logs a warning and skips server start if parsing fails

### Authentication

| Field | Default | Notes |
| --- | --- | --- |
| `auth.mode` | `off` | Supported modes are effectively `off` and `oidc`. Any other string falls back to `off`. |
| `auth.protect_status` | `true` | Only meaningful when `auth.mode=oidc`. |
| `auth.protect_otlp_http` | `true` | Only meaningful when `auth.mode=oidc`. |
| `auth.protect_otlp_grpc` | `false` | Only meaningful when `auth.mode=oidc`. |

### OIDC settings

| Field | Default |
| --- | --- |
| `auth.oidc.issuer` | empty |
| `auth.oidc.jwks_url` | `null` |
| `auth.oidc.client_id` | `null` |
| `auth.oidc.audiences` | `[]` |
| `auth.oidc.required_scopes` | `[]` |
| `auth.oidc.cache_ttl_ms` | `60_000` |
| `auth.oidc.leeway_sec` | `60` |
| `auth.oidc.http_timeout_ms` | `3000` |

Important behaviour:

- `auth.mode=oidc` is not enough on its own; the OIDC validator also requires either `issuer` or `jwks_url`
- without that supporting OIDC configuration, the validator is unavailable even if the mode string says `oidc`

## Update Manager

| Field | Default | Notes |
| --- | --- | --- |
| `update.enabled` | `false` | Enables the update manager. |
| `update.update_dir` | `updates` | Directory used for staged bundles and applied archives. |
| `update.bundle_name` | `tracey.update` | Staged bundle filename. |
| `update.signature_name` | `tracey.update.sig` | Signature filename. |
| `update.metadata_name` | `tracey.update.meta.json` | Metadata filename. |
| `update.local_channel` | `production` | Local policy channel. |
| `update.shared_key` | `tracey-dev-key-change-me` | Shared secret used for bundle verification. |
| `update.poll_interval_ms` | `5000` | Update check interval. |
| `update.handoff_timeout_ms` | `10_000` | Zero-downtime hand-off timeout. |

### Remote update settings

| Field | Default |
| --- | --- |
| `update.remote.enabled` | `false` |
| `update.remote.base_url` | `https://updates.example.com/tracey` |
| `update.remote.metadata_path` | `tracey.update.meta.json` |
| `update.remote.bundle_path` | `tracey.update` |
| `update.remote.signature_path` | `tracey.update.sig` |
| `update.remote.ca_cert_path` | `null` |
| `update.remote.client_identity_path` | `null` |
| `update.remote.timeout_ms` | `8000` |

Important behaviour:

- if `update.shared_key` is blank after overrides, sanitisation disables the update manager entirely
- remote fetching requires both `ca_cert_path` and `client_identity_path`; otherwise the fetch step fails
- the update manager records applied, staged, rejected, ignored, and failed outcomes to storage as `update_record`

## Loader

These settings apply to the separate `tracey-loader` binary.

| Field | Default | Notes |
| --- | --- | --- |
| `loader.enabled` | `true` | Enables loader mode. `tracey-loader` exits if this is false. |
| `loader.state_dir` | `loader` | Loader state root. |
| `loader.discovery_bind_addr` | `0.0.0.0:47989` | UDP gossip bind address. |
| `loader.discovery_broadcast_addr` | `255.255.255.255:47989` | UDP gossip broadcast address. |
| `loader.advertise_addr` | `null` | Optional advertised peer address. |
| `loader.transfer_listen_addr` | `0.0.0.0:47988` | HTTP transfer bind address. |
| `loader.transfer_public_addr` | `null` | Optional externally advertised HTTP address. |
| `loader.announce_interval_ms` | `1500` | Gossip interval. |
| `loader.sync_interval_ms` | `5000` | Peer-sync interval. |
| `loader.ttl_ms` | `10_000` | Loader announcement TTL. |
| `loader.request_timeout_ms` | `3000` | HTTP fetch timeout for peer transfers. |
| `loader.handoff_timeout_ms` | `10_000` | Handoff timeout when promoting a fetched core. |
| `loader.integrity_check_interval_ms` | `30_000` | How often the loader manifest timestamp is refreshed. |
| `loader.rollback_window_ms` | `120_000` | Probation window before the new core becomes distributable. |
| `loader.bootstrap_version` | `null` | Optional fallback version string used only when seeding metadata for an existing core. |

Important behaviour:

- the loader requires `update.shared_key` or `discovery.shared_key`; without one of them it refuses to start
- artefact verification prefers `update.shared_key`; loader gossip prefers `discovery.shared_key` when present
- if the current core binary exists but metadata and signature do not, the loader generates them locally
- peer redistribution only occurs for production-channel cores outside the rollback probation window

## Stimuli / AER Bridge

| Field | Default | Notes |
| --- | --- | --- |
| `stimuli.enabled` | `false` | Enables UDP AER ingest and posture/event egress. |
| `stimuli.listen_addr` | `0.0.0.0:48100` | Local UDP bind address. |
| `stimuli.peer_addr` | `null` | Optional outbound peer address. |
| `stimuli.flush_interval_ms` | `500` | Outbound flush interval. |
| `stimuli.posture_interval_ms` | `2000` | Posture announcement interval. |
| `stimuli.max_batch` | `128` | Maximum buffered frames per flush. |
| `stimuli.max_packet_bytes` | `8192` | Maximum UDP payload size. |

Important behaviour:

- if `stimuli.listen_addr` is blank, sanitisation disables the bridge

## Environment Override Coverage

The code supports both `TRACEY_*` and `NM_*` aliases for many settings. Coverage is selective.

### Global fuzzy settings

- `TRACEY_FUZZY_ENABLED`
- `TRACEY_FUZZY_ORDER`
- `TRACEY_FUZZY_UNCERTAINTY`
- `TRACEY_FUZZY_EDGE_BIAS`
- `TRACEY_FUZZY_AARNN_WEIGHT`
- `TRACEY_FUZZY_SECURITY_WEIGHT`

### Discovery, update, and loader

- `TRACEY_DISCOVERY_SHARED_KEY`
- `TRACEY_UPDATE_SHARED_KEY`
- `TRACEY_UPDATE_LOCAL_CHANNEL`
- `TRACEY_LOADER_ROLLBACK_WINDOW_MS`

### TraceyGuard

- `TRACEY_GUARD_ENABLED`
- `TRACEY_GUARD_OVERHEAD_PCT`
- `TRACEY_GUARD_POLL_MS`
- `TRACEY_GUARD_REMOTE_TTL_MS`

### TraceyBan

- `TRACEY_BAN_ENABLED`
- `TRACEY_BAN_AUTO_ELEVATE_ROOT`
- `TRACEY_BAN_SUDO_PROGRAM`
- `TRACEY_BAN_SUDO_NON_INTERACTIVE`
- `TRACEY_BAN_USE_SUDO_FOR_ACTIONS`
- `TRACEY_BAN_INHERIT_GLOBAL_FUZZY`
- `TRACEY_BAN_STATE_PATH`
- `TRACEY_BAN_MAX_ADVERTISED_IPS`
- `TRACEY_BAN_REMOTE_TTL_MS`
- `TRACEY_BAN_UNBAN_CHECK_MS`
- `TRACEY_BAN_PERSIST_INTERVAL_MS`
- `TRACEY_BAN_MIN_SAMPLES`
- `TRACEY_BAN_FUZZY_MIN_RISK`
- `TRACEY_BAN_FUZZY_MIN_CONFIDENCE`
- `TRACEY_BAN_FUZZY_RETRY_REDUCTION`
- `TRACEY_BAN_FUZZY_ENABLED`
- `TRACEY_BAN_FUZZY_ORDER`
- `TRACEY_BAN_FUZZY_UNCERTAINTY`
- `TRACEY_BAN_FUZZY_EDGE_BIAS`
- `TRACEY_BAN_FUZZY_AARNN_WEIGHT`
- `TRACEY_BAN_FUZZY_SECURITY_WEIGHT`

### Storage

- `TRACEY_STORAGE_PATH`
- `TRACEY_STORAGE_MAX_BYTES`
- `TRACEY_STORAGE_MAX_TOTAL_BYTES`
- `TRACEY_STORAGE_RETAIN_LINES`
- `TRACEY_STORAGE_COMPACT_INTERVAL_MS`
- `TRACEY_STORAGE_ROTATE_ARCHIVES`
- `TRACEY_STORAGE_SUMMARY_TOP_KEYS`

### Refiner

- `TRACEY_REFINER_ENABLED`
- `TRACEY_REFINER_SOURCE`
- `TRACEY_REFINER_SERVICE`
- `TRACEY_REFINER_HEALTH_URL`
- `TRACEY_REFINER_SECURITY_FEED_PATH`
- `TRACEY_REFINER_POLL_INTERVAL_MS`
- `TRACEY_REFINER_TIMEOUT_MS`

### Embedded collectors

- `TRACEY_EMBEDDED_ENABLED`
- `TRACEY_EMBEDDED_INTERVAL_MS`
- `TRACEY_EMBEDDED_JETSON_ENABLED`
- `TRACEY_EMBEDDED_MAX_THERMALS`
- `TRACEY_EMBEDDED_MAX_DISKS`
- `TRACEY_EMBEDDED_MAX_INTERFACES`
- `TRACEY_EMBEDDED_PROCESS_ENABLED`
- `TRACEY_EMBEDDED_PROCESS_TOP_N`
- `TRACEY_EMBEDDED_PROCESS_WINDOW_MS`
- `TRACEY_EMBEDDED_PROCESS_MAX`
- `TRACEY_EMBEDDED_GPU_ENABLED`
- `TRACEY_EMBEDDED_GPU_SYSFS_ENABLED`
- `TRACEY_EMBEDDED_GPU_NVML_ENABLED`
- `TRACEY_EMBEDDED_GPU_ROCM_ENABLED`
- `TRACEY_EMBEDDED_GPU_MAX_DEVICES`

### Prometheus pertinent-log export

- `TRACEY_PROMETHEUS_LOG_EXPORT_ENABLED`
- `TRACEY_PROMETHEUS_LOG_EXPORT_URL`
- `TRACEY_PROMETHEUS_LOG_EXPORT_PROBE_PATH`

### Auth and OIDC

- `TRACEY_AUTH_MODE`
- `TRACEY_OIDC_PROTECT_STATUS`
- `TRACEY_OIDC_PROTECT_OTLP_HTTP`
- `TRACEY_OIDC_PROTECT_OTLP_GRPC`
- `TRACEY_OIDC_ISSUER`
- `TRACEY_OIDC_JWKS_URL`
- `TRACEY_OIDC_CLIENT_ID`
- `TRACEY_OIDC_AUDIENCE`, `TRACEY_OIDC_ALLOWED_AUDIENCES`, `TRACEY_OIDC_AUDIENCES`
- `TRACEY_OIDC_REQUIRED_SCOPE`, `TRACEY_OIDC_REQUIRED_SCOPES`
- `TRACEY_OIDC_CACHE_TTL_MS`
- `TRACEY_OIDC_LEEWAY_SEC`
- `TRACEY_OIDC_HTTP_TIMEOUT_MS`

The same keys are also accepted with the `NM_` prefix.

## Sanitisation and Automatic Disable Rules

The sanitisation pass in `Config::sanitize()` is operationally significant.

### Automatic disable rules

The following conditions disable subsystems automatically:

- blank `discovery.shared_key` disables discovery
- blank `update.shared_key` disables the update manager
- blank `refiner.health_url` disables Refiner tracking
- blank `status.listen_addr` disables the status API
- disabled status also disables Prometheus pertinent-log export
- blank `prometheus_log_export.server_url` disables Prometheus pertinent-log export
- blank `stimuli.listen_addr` disables the stimuli bridge

### Automatic normalisation rules

The following values are normalised automatically:

- `assessment_quorum` is clamped into `1..=agents`
- `storage.max_total_bytes` is raised if it would otherwise be below `storage.max_bytes`
- TraceyBan blank `agent_id` is replaced from the top-level `agent_id`
- TraceyBan blank jail names become `tracey-jail-N`
- TraceyBan blank `backend` becomes `tracey_event`
- TraceyBan blank `shell` becomes `/bin/sh`
- TraceyBan blank `sudo_program` becomes `sudo`
- empty `event_ip_keys` restore the default IP-key list

### Range clamping

Numerous fields are clamped to defensive bounds, including:

- top-level capacities and timing values
- fuzzy order and weights
- storage budgets and intervals
- discovery, telemetry, update, loader, governance, coordination, and stimuli intervals
- TraceyGuard probe, TMR, correlation, and snapshot limits
- TraceyBan retry counts, ban windows, action timeouts, and fuzzy thresholds
- OIDC cache TTL, leeway, and HTTP timeout

If you provide out-of-range values in JSON or environment variables, the runtime will generally continue with the clamped value rather than failing fast.
