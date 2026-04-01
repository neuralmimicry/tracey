# Tracey Workflow Analysis

## Executive Summary

Tracey is structured as an asynchronous, multi-subsystem runtime that tries to solve three related problems at once:

1. normalise many kinds of operational and security signal into a common event model
2. score and decide on those signals through swarm-style consensus rather than a single detector
3. keep the resulting behaviour observable, governable, and replaceable at runtime

The repository already contains substantial implementation work in those areas, but the code also makes its present intent clear: it is a hybrid of real integrations and synthetic exercise paths.

Examples of that split are important when interpreting the project:

- the runtime always starts synthetic sensors
- `TraceyGuard` discovers real GPU identities where possible, but its probe execution path is still synthetic and CPU-executed
- the status, discovery, exporter, and loader planes are real networked control surfaces
- the update, supervisor, and loader subsystems implement actual binary staging, promotion, and rollback

A fair characterisation of the current codebase is therefore: **an experimental distributed monitoring and response runtime with production-style control and lifecycle features, backed by a mixture of real telemetry ingestion and synthetic self-exercise**.

## Intent and Goals Identified from the Code

### 1. Shared event normalisation

The entire crate pivots around `src/event.rs`, which defines a single `Event` structure used by sensors, telemetry, TraceyGuard, Refiner tracking, the stimuli bridge, and downstream storage.

The design intent is clear:

- every producer emits the same base fields: `id`, `ts_ms`, `source`, `kind`, `signal`, `severity`
- rich producer-specific context lives in string attributes rather than separate per-source structs on the bus
- downstream consumers can score, route, or persist events without knowing where they came from

### 2. Swarm scoring rather than single-process thresholding

`src/swarm/agent.rs`, `src/swarm/learning.rs`, and `src/swarm/coordinator.rs` show that Tracey is not meant to be a simple threshold alarm.

Instead, the intended flow is:

- independent agents subscribe to a shared broadcast bus
- each agent scores the same event against its own adaptive baseline
- the coordinator waits for quorum or expiry before finalising a decision
- elected leaders share learning snapshots and focus directives so the swarm converges over time

### 3. Governance as a first-class control plane

`src/governance.rs` and the coordinator’s vote-processing loop show that Tracey wants operational posture to be dynamic.

The runtime treats posture as a stateful control layer that can:

- raise or lower the decision threshold
- permit or suppress active response
- permit or suppress shutdown decisions
- gate updates and some remote telemetry behaviour
- reflect cluster conditions rather than only static configuration

### 4. Distributed coordination and delegated control surfaces

`src/coordination.rs`, `src/discovery.rs`, `src/status.rs`, and `src/prometheus_export.rs` indicate a strong emphasis on multi-node operation.

Tracey is trying to solve not only “what is happening?” but also:

- which nodes should currently lead
- which node should proxy status requests
- which node should expose the pertinent Prometheus log series for the cluster
- how peer intel such as bans or GPU faults should change local interpretation

### 5. Mutable-core lifecycle management

`src/update.rs`, `src/supervisor.rs`, `src/loader.rs`, and `scripts/install-service.sh` reveal a separate goal: keeping the service up while the executable changes.

That lifecycle goal has several layers:

- stage and verify updates locally
- hand over from one process to another without a hard stop
- distribute production cores between peers
- keep rollback state so bad promotions can be undone automatically

## Bootstrap Workflow

The runtime bootstrap in `src/lib.rs` proceeds in a fixed orchestration pattern.

### Step 1. CLI mode selection

`run_tracey()` first checks for special modes:

- `sign-update`: runs the offline bundle-signing helper from `src/update.rs`
- `--version` or `-V`: prints the crate version
- `--supervisor`: if `TRACEY_SUPERVISED` is absent, runs the supervisor loop instead of the normal runtime

### Step 2. Config and privilege preparation

`Config::load()` then loads defaults, an optional JSON file from `TRACEY_CONFIG`, environment overrides, and a sanitisation pass.

Important config-backed bootstrap behaviour:

- discovery is disabled automatically if its shared key is blank
- updates are disabled automatically if their shared key is blank
- Refiner tracking is disabled automatically if `health_url` is blank
- status is disabled automatically if `status.listen_addr` is blank
- the Prometheus log exporter is disabled automatically if status is disabled
- TraceyBan fills missing jail names, shell paths, and event IP keys during sanitisation

Tracey then calls `tracey_ban::maybe_elevate_for_tracey_ban()`, which may re-exec the process via `sudo` if enabled jails require root-protected log paths or firewall-style action commands.

### Step 3. Core primitives

The runtime creates:

- a cooperative shutdown handle and listener
- a bounded broadcast event bus
- asynchronous JSONL storage
- inventory correlation state
- assessment, governance, directive, learning, and decision channels
- governance state behind `Arc<RwLock<...>>`
- distributed intel hubs for bans and GPU faults

### Step 4. Coordination and leader-sensitive components

Before any producer is started, Tracey creates:

- the coordination subsystem
- the coordinator runtime
- the Prometheus pertinent-log exporter
- swarm agents

This matters because later subsystems depend on current leadership information.

### Step 5. Optional and peripheral runtimes

Only after the swarm core is wired does Tracey start the other modules:

- status API
- synthetic sensors
- embedded collectors
- stimuli bridge
- telemetry ingest
- TraceyBan
- discovery gossip
- asset feed ingestion
- Refiner tracking
- update manager

That startup order reflects the project’s priorities: build the decision-making core first, then connect producers and external control surfaces around it.

## Configuration Workflow and Runtime Assumptions

### Precedence and normalisation

`src/config.rs` implements:

`defaults < JSON config file < env overrides < sanitisation`

Environment overrides mostly follow two parallel naming conventions:

- `TRACEY_*`
- `NM_*`

This is not exhaustive across every field, but the file exposes overrides for the most operationally significant knobs, especially fuzzy scoring, discovery, update keys, embedded collectors, TraceyGuard, TraceyBan, storage, Refiner, OIDC, and selected loader settings.

### Default profile that falls out of the code

A plain `cargo run` with no configuration file currently means:

- six scoring agents
- assessment quorum of four
- decision threshold of `0.75`
- governance and coordination enabled
- discovery enabled on UDP `47990`
- status enabled on `0.0.0.0:48000`
- OIDC support present but not enabled
- Prometheus pertinent-log export enabled and probing an external default URL
- embedded collectors enabled on Linux
- TraceyGuard enabled
- TraceyBan, telemetry ingest, Refiner tracking, updates, asset feed, and stimuli bridge disabled
- synthetic sensors enabled with no config switch to turn them off

That profile is code-backed, not inferred from the old documentation.

## Event Producer Matrix

| Producer | Module | Default | Event kind | Signal semantics | Persistence behaviour |
| --- | --- | --- | --- | --- | --- |
| Synthetic sensors | `src/sensors.rs` | On | Varies by sensor | Approximate 0-1 baseline with injected anomalies | Published and recorded immediately |
| Embedded collectors | `src/embedded.rs` | On on Linux | `system_metric` | `signal` is a normalised ratio; raw value and unit are attributes | Published and recorded immediately |
| Telemetry ingest | `src/telemetry.rs` | Off | `observability` | `signal` is the raw metric value | Published and recorded immediately |
| Refiner health | `src/refiner_tracking.rs` | Off | `observability` | Fixed severity-to-signal mapping | Published and recorded immediately |
| Refiner findings | `src/refiner_tracking.rs` | Off | `observability` | Finding severity mapped to signal, enriched with CVE/CVSS context | Published and recorded immediately |
| TraceyGuard probe results | `src/tracey_guard.rs` | On | `observability` | Derived from probe state, mismatch ratio, stress, and remote corroboration | Published and recorded immediately |
| TraceyBan ban events | `src/tracey_ban.rs` | Off | `network_flow` | Fixed ban/unban signals plus fuzzy metadata attributes | Published and recorded immediately |
| Stimuli/AER ingress | `src/stimuli.rs` | Off | Varies | Byte value scaled to `0.0..1.0` | Published only by the bridge itself |
| Discovery presence | `src/discovery.rs` | On | Not an `Event` | N/A | Stored as `agent_presence` |
| Asset feed | `src/assets.rs` | Off | Not an `Event` | N/A | Stored as `host_observation` and possibly `unmanaged_host` |

## Event Model and Signal Semantics

`src/event.rs` is deliberately minimal.

Important implications from the code:

- `EventKind` is a coarse taxonomy, not a full schema: `system_metric`, `network_flow`, `user_action`, `automation_action`, and `observability`
- signal meaning is producer-specific; the coordinator does not re-normalise it centrally
- severity carries its own downstream weight through `Severity::weight()`
- attributes are the only place where most source-specific semantics live

This means a Tracey consumer must not assume every `signal` is directly comparable across sources:

- embedded metrics use a normalised ratio as the signal and store the raw reading separately
- telemetry ingest uses the raw metric value as the signal
- Refiner uses severity buckets as the signal
- TraceyGuard derives a synthetic risk-like signal from probe outcomes and environment
- synthetic sensors already operate near a 0-1 range

## Swarm Scoring Workflow

### Adaptive baseline model

`src/swarm/learning.rs` keeps per-`EventKind` online statistics using Welford’s algorithm.

For each event, the scorer derives:

- count, mean, and standard deviation for that kind
- a `learned_confidence` based on how close count is to `min_samples`
- a scaled absolute z-score with a minimum standard deviation floor of `0.05`
- edge and novelty memberships using both z-score and change from the previous signal

### Context-aware fuzzy inputs

The scorer then folds in contextual dimensions.

#### Security context

`security_context()` increases risk when the event:

- comes from a source name containing `security` or `refiner`
- looks like an AARNN-derived event
- carries `cve`, `cvss`, `finding_id`, or `finding_severity`
- explicitly marks `anomaly=true`

#### Metric context

`metric_context()` currently biases a selected set of embedded metrics, especially:

- GPU power, clocks, fan speed, encoder and decoder utilisation
- memory and swap pressure
- some `embedded` source metrics in general

#### AARNN context

Events from source `aarnn` or events carrying `aarnn_output_index` receive extra contextual weight.

### Type-n fuzzy refinement

If fuzzy scoring is enabled:

1. a Type-1 risk is derived from normal, suspicious, and anomalous membership functions
2. uncertainty is derived from learned confidence, volatility, and ambiguity
3. the configured fuzzy order recursively refines the risk interval
4. context bias from edge, security, metric, and AARNN factors nudges the interval centre
5. confidence is recomputed from learned confidence and interval width

If fuzzy scoring is disabled, Tracey falls back to a sigmoid over the absolute z-score.

### Learning propagation

Leaders periodically broadcast a `LearningSnapshot` so agents merge global baselines using `learning_merge_alpha`. The coordinator also pushes focus directives so agents can temporarily boost scoring weight for the hottest `EventKind`.

## Assessment, Consensus, and Action Workflow

### Agent-side behaviour

Each swarm agent in `src/swarm/agent.rs`:

- receives every event on the broadcast bus
- merges learning snapshots when they arrive
- applies focus directives when they change
- scores the event
- maps the resulting risk and confidence through `ActionPolicy`
- emits an `Assessment`
- updates exponential moving averages used for governance voting

### Governance vote emission

Agents periodically emit `GovernanceVote` values derived from their risk and confidence EMAs. If the rebel simulation is enabled, an agent can occasionally invert its posture vote via `Posture::rebel_flip()`.

### Coordinator-side consensus

The coordinator in `src/swarm/coordinator.rs` does not finalise every event immediately.

The actual workflow is:

1. accept assessments only when the local node is a current coordinator
2. if there are multiple coordinators, only handle an event when `event_id % leader_count == leader_rank`
3. accumulate assessments until quorum is reached or the per-event TTL expires
4. average risk, confidence, signal, and fuzzy telemetry across the received assessments
5. compare mean risk against the current governance-adjusted decision threshold
6. run `ActionPolicy::decide()` only when the mean risk clears that threshold
7. downgrade unsafe actions through `enforce_response_mode()` when active response or shutdown are not allowed
8. record the final decision, publish it on the decision tap, and feed learning/tuning loops

### Action downgrades

The coordinator enforces two key safety rails:

- when `active_response` is false, anything stronger than `Alert` is downgraded to `Alert`
- when shutdown is disabled, `Shutdown` is downgraded to `Isolate`

The coordinator currently logs a loud error for a shutdown decision, but it does not implement an actual host shutdown routine.

## Governance Workflow

`src/governance.rs` models posture as `relaxed`, `balanced`, `strict`, or `lockdown`.

The posture workflow is:

1. agents vote periodically
2. only leaders process governance votes
3. old votes expire after `vote_ttl_ms`
4. votes below the minimum confidence are ignored
5. remaining votes are weighted by confidence
6. the winning posture must exceed a separate governance decision threshold
7. the new posture is applied to feature gates and the decision threshold

### What posture changes actually do

The code applies posture to runtime behaviour as follows:

- `relaxed`: raises the decision threshold slightly, allows remote telemetry only if configured, and disables active response
- `balanced`: leaves the base decision threshold unchanged
- `strict`: lowers the decision threshold, enables active response if configured, and disables updates
- `lockdown`: lowers the threshold further, enables active response, allows shutdown if configured, and disables updates

Notably, telemetry itself remains enabled when configured; posture mostly changes remote telemetry allowance and response/update controls.

## Coordination Workflow

`src/coordination.rs` tracks peer presence and computes several distributed roles.

### Election inputs

Each presence record contributes:

- CPU core count
- observed latency based on gossip receive time
- a deterministic shared-key hash score
- capability tags from the host and optional Slurm detection
- optional Prometheus probe results

### Resulting roles

The subsystem decides:

- whether the local node is a coordinator
- the local coordinator rank and total leader count
- the preferred status proxy target
- the preferred Prometheus pertinent-log exporter

### Proxy and exporter logic

The status proxy is selected as the lowest-latency leader.

The Prometheus pertinent-log exporter is selected by a separate ranking that strongly prefers a ready probe with lower latency and higher measured bandwidth to the configured Prometheus tenant.

This is why the Prometheus exporter and status proxy are separate concepts in the status payload.

## Discovery Workflow

`src/discovery.rs` is more than simple peer discovery.

### Announcement contents

Each gossip announcement can carry:

- agent identity and timestamp
- optional advertised address and status address
- capability data
- coordinator state and deterministic score
- optional ban advertisement
- optional fault advertisement
- optional Slurm snapshot
- optional Prometheus probe data

### Authentication model

Announcements are signed with a keyed BLAKE3 digest over selected fields. Verification uses a constant-time comparison.

This gives Tracey:

- authenticity tied to a shared secret
- no confidentiality
- no per-peer identity beyond the shared-key trust domain

### Validation and sanitisation

Before accepting a peer announcement, the code:

- checks signature shape and digest equality
- enforces TTL and future-skew bounds
- validates text fields and capability tag limits
- sanitises ban and fault advertisements
- sanitises and optionally drops invalid Slurm snapshots

Discovery therefore acts as both a peer-presence plane and a bounded remote-intel ingestion path.

## Inventory and Asset Workflow

`src/inventory.rs` correlates two streams:

- `AgentPresence` values from discovery
- `HostObservation` values from asset feeds

The current unmanaged-host rule is simple: if a host observation arrives for a `host_id` that does not match any recent agent presence `agent_id`, Tracey records an `unmanaged_host` record.

This means asset feeds and agent identities must use the same host identity convention if unmanaged-host reporting is expected to be meaningful.

## Status and Control Plane Workflow

`src/status.rs` exposes the main operator-facing HTTP API.

### Local-versus-proxied snapshots

When a client hits `/status`, a follower may forward that request to the currently selected proxy node unless the request already carries `x-tracey-proxy-hop: 1`.

The effect is:

- one node can act as the cluster-facing status entry point
- clients get a proxy-normalised snapshot rather than having to poll every peer directly
- malformed proxy responses are syntax- and semantics-validated before being returned

### Current status payload contents

The snapshot currently includes:

- coordination role and proxy/exporter information
- posture and decision threshold
- active-response, shutdown, update, telemetry, and discovery flags
- TraceyBan local and remote summaries
- TraceyGuard summary and snapshot when enabled
- optional Slurm snapshot
- Prometheus probe data for the local node and elected exporter

### TraceyGuard control API

`/control/tracey_guard` allows runtime mutation of:

- enabled state
- deep-dive mode
- overhead budget percentage
- TMR enablement
- maximum parallel tasks
- one-shot force-scan epoch

This is operationally powerful and therefore a major security-sensitive surface.

### Important security nuance

The status and TraceyGuard routes use `AuthGate`, but authorisation only does anything when `auth.mode` is set to `oidc`. With the default `off` mode, the routes are effectively open.

The Prometheus metrics route does not pass through `AuthGate` at all.

## Prometheus Pertinent-Log Export Workflow

`src/prometheus_export.rs` builds a leader-elected aggregation path separate from the swarm decision loop.

### Local record selection

The exporter subscribes to both events and decisions, then keeps only records that meet the “pertinent” filters.

Examples from the code:

- TraceyGuard faults are kept when high severity or above the configured signal threshold
- TraceyBan records are kept when not low severity or above the configured signal threshold
- selected embedded GPU and memory metrics are kept only when high severity
- swarm decisions are kept when alerting, or when monitor decisions still exceed `min_decision_risk`

### Follower-to-leader forwarding

If the local node is not the elected exporter:

- pertinent records are queued locally
- followers periodically batch and sign them with a shared-key digest
- batches are sent to the elected exporter’s `/prometheus/ingest` route

If the local node is the exporter:

- it maintains the time-bounded series map used to render `/metrics`
- it hides the series from followers

### Exporter security model

The ingest route does not use OIDC. Instead it enforces:

- batch size and TTL limits
- presence of `x-tracey-prometheus-signature`
- keyed-digest verification
- exporter-role ownership, returning conflict on followers

## Telemetry Workflow

`src/telemetry.rs` supports two ingestion modes.

### Prometheus scraping

When enabled, Tracey:

- collects endpoints from config, autodiscovery, and selected environment variables
- skips remote endpoints unless config and governance both allow them
- scrapes each endpoint on the configured interval
- parses Prometheus text exposition line-by-line
- enforces allowlists via exact names and prefixes
- deduplicates against recent Prometheus samples when Prometheus is preferred over OTLP

### OTLP receivers

When enabled, Tracey starts:

- an OTLP gRPC metrics service on `grpc_addr` when `enable_grpc` is true
- an OTLP HTTP endpoint at `/v1/metrics` on `http_addr` when `enable_http` is true

The code supports gauges, sums, histograms, exponential histograms, and summaries by turning them into scalar values.

### Authorisation nuance

OTLP HTTP and OTLP gRPC routes have separate protect flags, but those gates are still inert until `auth.mode=oidc` and OIDC config are supplied.

## Embedded Collector Workflow

`src/embedded.rs` is a substantial Linux collector in its own right.

### Data sources currently read

The collector reads from:

- `/proc/stat`
- `/proc/meminfo`
- `/proc/diskstats`
- `/proc/net/dev`
- `/proc/<pid>/stat`, `statm`, and `io`
- `/proc/self/mounts`
- `/sys/class/thermal`
- `/sys/class/power_supply`
- Jetson-specific paths under `/sys/devices/...` and `/sys/bus/i2c/drivers/ina3221x`
- GPU backends via sysfs, NVML, and ROCm SMI where available

### Metric families currently emitted

The code emits, among others:

- `cpu_usage`
- `mem_used`, `mem_available`, `mem_app_used`, `mem_bufcache`, `swap_used`
- `thermal_temp`
- `disk_read_bps`, `disk_write_bps`, `disk_used_bytes`, `disk_total_bytes`
- `net_rx_bps`, `net_tx_bps`
- `battery_capacity_percent`, `battery_power`, `battery_voltage`, `battery_current`
- `process_cpu_percent`, `process_mem_rss_bytes`, `process_io_bps`
- `gpu_util_percent`, `gpu_temp_c`, `gpu_power_w`, `gpu_mem_total_bytes`, `gpu_mem_used_bytes`, `gpu_clock_graphics_mhz`, `gpu_clock_memory_mhz`, `gpu_fan_speed_percent`, `gpu_encoder_util_percent`, `gpu_decoder_util_percent`
- Jetson-specific metrics such as `jetson_gpu_load`, `jetson_gpu_freq`, `jetson_fan_rpm`, `jetson_fan_pwm`, and `jetson_power`

These metrics matter beyond observability because TraceyGuard uses embedded GPU metrics to build device stress context.

## TraceyGuard Workflow

`src/tracey_guard.rs` is one of the most complex subsystems in the repository.

### What it is trying to do

The code is trying to bring TraceyGuard-style GPU health probing into Tracey’s async runtime while preserving:

- periodic probe scheduling
- workload-aware sampling
- fuzzy risk scoring over probe results
- remote fault corroboration via gossip
- operator control over scan intensity
- state transitions such as healthy, suspect, quarantined, and deep-test

### What it actually does today

The runtime discovers GPU identities through NVML, ROCm SMI, or sysfs. However, the probe execution path is synthetic:

- `execute_probe_kernel()` computes deterministic payloads in CPU worker threads
- stress-based fault injection simulates mismatches
- embedded GPU telemetry influences scheduling and synthetic fault likelihood
- no actual on-device GPU kernels are launched by the current implementation

That makes TraceyGuard a meaningful scheduler/correlation prototype, but not yet a direct hardware test harness.

### Device and state workflow

1. discover real GPU identities if possible, otherwise create synthetic devices
2. maintain per-device telemetry context from embedded GPU events
3. build per-probe schedules from config
4. dispatch scheduled probes subject to an overhead budget and max-parallel semaphore
5. score probe results with a dedicated adaptive scorer
6. update a Beta-distribution-style reliability model per device
7. transition device states based on reliability, confidence, remote corroboration, and failure streaks
8. publish local faults into the fault-intel hub and to the event bus
9. refresh a bounded status snapshot

### TMR workflow

The TMR path is also synthetic. It compares pseudo-fingerprints across suspect and healthy devices and records disagreement as a fault event. It is not validating actual replicated GPU output streams.

### Status-model nuance

The status structures include a `condemned` state, but the current transition logic does not automatically move devices into `Condemned`.

## TraceyBan Workflow

`src/tracey_ban.rs` implements a native jail subsystem with both real operational hooks and Tracey-specific fuzzy scoring.

### Jail inputs

A jail can currently draw from:

- tailed log files (`file`, `polling`, `hybrid`, `auto`)
- events already on the Tracey bus (`event`, `tracey_event`, `hybrid`, `auto`)
- upstream-style filter files containing `failregex` and `ignoreregex`

### Detection pipeline

For each jail, the runtime:

1. normalises TraceyBan placeholder syntax into Rust regexes
2. tails configured log files with persisted offsets or inspects bus events for candidate IPs
3. filters ignored IPs and ignored regex matches
4. keeps a rolling failure window per IP
5. reduces the effective retry threshold when remote peers report the same IP
6. optionally applies fuzzy scoring to reduce the retry threshold further for high-confidence attacks
7. executes ban and unban action hooks
8. persists active bans, offsets, and ban counters to disk
9. advertises current bans over discovery gossip

### Privilege model

The subsystem contains explicit root-awareness:

- it detects root-protected log path prefixes
- it detects firewall-style action commands
- it can re-exec the process via `sudo`
- action hooks can run via `sudo` even when the main process is not root

This is operationally useful but also one of the more security-sensitive parts of the repository.

## Refiner Tracking Workflow

`src/refiner_tracking.rs` combines two distinct inputs:

- polling a health endpoint for service availability and queue pressure
- tailing an append-only JSONL security feed for findings relevant to the configured service name

Important code-backed behaviour:

- health changes only emit events on state change or when unhealthy
- queue utilisation above `0.75` degrades health even if the endpoint still returns `ok`
- findings are only converted to events when the `service` or `image` matches the configured service name
- findings attach CVE, CVSS, scanner, status, title, and finding ID attributes when present

## Stimuli and AER Workflow

`src/stimuli.rs` and `src/aer.rs` implement a UDP bridge around a compact binary codec.

### Outbound path

- bus events other than `aarnn` are converted into AER frames
- posture changes are also converted into dedicated AER addresses
- frames are batched and sent to the configured peer

### Inbound path

- incoming AER frames are decoded into synthetic `aarnn` events
- known Tracey event addresses are mapped back to `EventKind` and `Severity`
- addresses above `AARNN_OUTPUT_BASE` are treated as AARNN output indices

The codec itself uses a magic header plus timestamp deltas and varints for compactness.

## Slurm Workflow

`src/slurm.rs` is a passive environment detector and status sampler.

The current implementation can:

- detect Podman-based Slurm topologies used by Continuum
- detect local/native Slurm via files, processes, commands, or environment variables
- probe controller health through `scontrol ping`
- derive cluster name from `scontrol show config` or config files
- classify node and job states into bounded counters
- advertise Slurm capability tags via discovery and coordination
- expose the snapshot in the status API

No events are published from Slurm; it is a snapshot-only subsystem at present.

## Storage Workflow

`src/storage.rs` owns a bounded asynchronous persistence pipeline.

### Write path

Producers send typed records to a dedicated storage task, which serialises each record as a single JSON line.

### Housekeeping path

On a timer, storage:

- flushes the active writer
- prunes stale archives beyond the configured count
- rotates the active log if `max_bytes` is exceeded and archive rotation is enabled
- otherwise compacts the active file in place to the configured tail length
- enforces a total byte budget across active and archived logs

### Compaction summary

When compaction is used, the new head of the log becomes a synthetic `log_summary` record describing the truncated section by type, key, and timestamp range.

## Update, Supervisor, and Loader Workflow

### OTA update manager

`src/update.rs` stages a new binary from either local files or an optional remote mTLS source, then verifies:

- bundle hash against metadata
- keyed BLAKE3 signature over `metadata || bundle`
- OS and architecture match
- channel match against `update.local_channel`

It then either:

- requests a supervised handoff through the supervisor request file, or
- spawns a replacement process directly and waits for the handoff token

### Supervisor

`src/supervisor.rs` is a tight process-management loop that:

- starts the child runtime with shutdown and handoff token paths in the environment
- restarts the child on exit with backoff
- applies staged update requests on the fly via a zero-downtime handoff path
- asks the old child to exit by writing a shutdown token file

### Loader

`src/loader.rs` extends the same idea into a service-grade wrapper around a mutable core.

The loader workflow is:

1. verify the loader binary against a persisted integrity manifest
2. load or seed the current core metadata and signature
3. start an HTTP transfer server and UDP loader gossip socket
4. run the current core under supervisor-style child management
5. announce the current core to peers when it is distributable
6. fetch newer production cores from peers when available
7. hand over to the staged core
8. promote the staged core into `loader/current`
9. enter a rollback probation window backed by a rollback marker file
10. restore the previous core automatically if the promoted core crashes during probation

The loader only redistributes production-channel cores and suppresses redistribution while rollback is pending.

## Service Installation Workflow

`scripts/install-service.sh` is effectively the supported operational bootstrap path for Linux `systemd` deployments.

The script does more than install a unit file:

- finds or builds both binaries
- chooses system or user scope
- installs the loader into a stable executable path
- seeds the mutable core into the state tree
- writes a minimal config and environment file
- writes a unit with `WorkingDirectory` pointed at the Tracey state directory
- reloads `systemd`, enables the service, and optionally starts it

This matters because the runtime relies heavily on relative paths. The installer deliberately controls the working directory so those paths land in the intended state tree.

## Safety and Resilience Controls Present in the Code

The repository does include a number of meaningful safety rails.

### Configuration and boundedness

- sanitisation clamps aggressive numeric settings
- some subsystems disable themselves when critical prerequisites are missing
- storage, exporter queues, snapshot sizes, and telemetry sampling all have explicit bounds

### Digest verification and constant-time comparisons

The code uses keyed BLAKE3 digests plus constant-time equality checks for:

- discovery announcements
- update bundles
- Prometheus exporter forwarding batches
- loader announcements

### Cooperative shutdown

Most long-running tasks honour the shared `ShutdownListener`, allowing orderly stop and handoff.

### Rollback and probation

The loader keeps rollback artefacts and a probation marker so a crashing promoted core can be reverted automatically.

### Input validation

Status proxy payloads, discovery announcements, Slurm snapshots, and loader announcements all receive dedicated semantic validation and normalisation.

## Operational Caveats the Documentation Must Keep Explicit

The code review surfaced several caveats that should remain prominent in the documentation.

### Default exposure and outbound traffic

By default Tracey will:

- bind an unauthenticated HTTP status API to all interfaces
- broadcast discovery gossip with a development placeholder key
- probe an external Prometheus URL for exporter role selection

### Synthetic activity

The runtime will also generate synthetic activity even on otherwise quiet hosts:

- synthetic sensors are always started
- TraceyGuard can create synthetic GPU devices and synthetic probe failures

### Symmetric trust model

The project uses shared-key MACs, not asymmetric signatures, for several distributed paths. Anyone with the shared key can impersonate an authorised peer within that trust domain.

### Route and state mismatches that are easy to overstate

- `/tracey_guard/deepdive` is currently an alternate route to the same snapshot shape, not a fundamentally different API
- the `condemned` GPU state exists in the model but is not currently reached automatically
- OTLP protection flags do nothing until OIDC mode is enabled

## Verification Snapshot

Local verification performed on **31 March 2026**:

```bash
cargo test --all-targets
```

Observed result:

- `99` unit and property tests passed in `src/lib.rs`
- `0` tests failed
- the binary entry points compiled and their zero-test harnesses passed
