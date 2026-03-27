# Tracey Workflow Analysis

## Intent and Goals
Tracey is an async, swarm-based monitoring and response runtime designed to:
1. Ingest heterogeneous local and external signals at high concurrency.
2. Convert signals into normalized event risk assessments using adaptive fuzzy scoring.
3. Reach resilient multi-agent consensus before taking response actions.
4. Gate behavior dynamically through governance posture and elected coordination.
5. Preserve an auditable timeline of all inputs, decisions, and control updates.

## End-to-End Runtime Workflow
1. **Bootstrap and wiring (`src/main.rs`)**
   - Loads config (`Config::load`) with defaults, file override, env override, and sanitization.
   - Creates shutdown primitive, event bus, storage pipeline, inventory tracker, and channel graph.
   - Starts optional subsystems: status API, telemetry collectors, embedded collectors, stimuli bridge, TraceyBan, TraceyGuard, discovery, asset feed, refiner tracking, and updater.
2. **Signal ingestion**
   - Synthetic sensors: `src/sensors.rs`
   - Embedded host metrics: `src/embedded.rs`
   - Prometheus + OTLP ingest: `src/telemetry.rs`
   - External assets: `src/assets.rs`
   - Refiner health/findings: `src/refiner_tracking.rs`
   - AER stimuli bridge: `src/stimuli.rs`
3. **Normalization and publication**
   - All producers emit common `Event` records (`src/event.rs`) through shared `EventBus` (`src/bus.rs`).
   - Producers attach semantic attributes (`metric`, `cve`, `finding_severity`, `aarnn_output_index`, etc.) for downstream fuzzy context.
4. **Swarm scoring and voting**
   - Agent workers (`src/swarm/agent.rs`) subscribe to bus and score events using `AdaptiveScorer` (`src/swarm/learning.rs`).
   - Agents emit:
     - `Assessment` values for decision consensus.
     - `GovernanceVote` values for posture control.
5. **Decision synthesis and policy enforcement**
   - Coordinator (`src/swarm/coordinator.rs`) aggregates assessments by event ID.
   - Quorum + TTL logic handles late/missing votes.
   - Action policy (`src/security.rs`) and response-mode constraints enforce safe action downgrades when active response or shutdown is disabled.
   - Optional adaptive tuning (`src/tuning.rs`) adjusts decision threshold over alert-rate windows.
6. **Governance and coordination**
   - Governance state (`src/governance.rs`) applies posture-specific gates:
     - threshold shift
     - active response enablement
     - shutdown enablement
     - update enablement
     - remote telemetry allowance
   - Coordination (`src/coordination.rs`) runs periodic leader election using weighted host score (CPU, latency, hash, capability tags).
7. **Security side-runtimes**
   - TraceyBan (`src/tracey_ban.rs`): jail-style detection/actions, ban persistence, cross-agent ban intelligence.
   - TraceyGuard (`src/tracey_guard.rs`): probe scheduling, fault correlation/state transitions, deep-dive/control APIs, remote fault intelligence.
8. **Distributed gossip and status/control plane**
   - Discovery (`src/discovery.rs`) signs and validates announcements, sanitizes remote advertisements, updates inventory/coordination state.
   - Status API (`src/status.rs`) exposes local and proxied runtime snapshots and TraceyGuard controls.
   - Auth gates (`src/auth.rs`) enforce optional OIDC policy on status/OTLP paths.
9. **Persistence, retention, and lifecycle**
   - Storage (`src/storage.rs`) writes JSONL records asynchronously and enforces rotation/compaction/total-byte budget.
   - Supervisor/update flows (`src/supervisor.rs`, `src/update.rs`) support staged signed updates and handoff signaling.
   - Shutdown (`src/shutdown.rs`) provides coordinated stop across all tasks.

## Module Responsibility Map
- `src/config.rs`: config schema, defaults, override precedence, sanitization bounds.
- `src/event.rs`: canonical event model.
- `src/swarm/*`: scoring, consensus, directive/learning feedback loops.
- `src/governance.rs`: posture and runtime feature gating.
- `src/coordination.rs`: leader election and proxy selection.
- `src/discovery.rs`: authenticated gossip + remote intel intake.
- `src/tracey_ban.rs`: ban detection/action + remote ban intel.
- `src/tracey_guard.rs`: GPU fault probes, correlation, control, remote fault intel.
- `src/status.rs`: runtime introspection and operational control surface.
- `src/storage.rs`: durable, bounded audit log.
- `src/telemetry.rs` / `src/embedded.rs` / `src/assets.rs` / `src/refiner_tracking.rs` / `src/stimuli.rs`: ingest and signal generation.
- `src/update.rs` / `src/supervisor.rs`: update integrity and process continuity.

## Safety and Resilience Controls
1. Config sanitization clamps unsafe bounds and disables subsystems when required secrets/keys are absent.
2. Discovery/status payload validators enforce semantic bounds and reject malformed data.
3. Constant-time digest comparisons are used for signature checks (`discovery`, `update`).
4. Response-mode guardrails prevent unsafe escalation when posture/config disallow it.
5. Storage and telemetry ingestion enforce bounded resource behavior (`max_samples`, archive budgets, TTL cleanup).
6. Shutdown is cooperative and uniform across all async workers.

## Verification Matrix
The suite now verifies precision/accuracy/function/safety/resilience across both existing and newly added tests:

- **Codec correctness and corruption handling**
  - `aer`: round-trip ordering, invalid magic, truncation, varint overflow.
- **Policy precision**
  - `security`: confidence gate and threshold transitions.
  - `governance`: posture mapping, gate toggles, threshold clamping.
  - `tuning`: window behavior, directional adjustments, bound enforcement.
- **Normalization and parsing robustness**
  - `assets`: host identity fallback order.
  - `telemetry`: metric line parsing, label unescaping, allowlist logic, deterministic dedup keys.
  - `auth`: bearer parsing, required-scope logic, algorithm filter.
  - `embedded`: `/proc` stat parsing and mapping helpers.
- **Coordination correctness**
  - `coordination`: deterministic score hashing, weighted election behavior, proxy latency preference.
  - `discovery` (existing): semantic validation and panic-safe fuzz/property checks.
  - `status` (existing): proxy payload semantic validation and panic-safe fuzz/property checks.
- **Runtime utility safety**
  - `shutdown`: listener unblock semantics.
  - `bus`: publish/subscribe delivery.
  - `config`: sanitizer bounds and key-dependent subsystem disablement.
  - `update`: signature helper determinism, URL normalization, artifact generation.
  - `inventory`: TTL purge logic.
  - `capabilities`: tag normalization/dedup.
  - `stimuli`: AER mapping correctness for event/kind/posture paths.

Latest local execution:

```bash
cargo test --all-targets
```

Result: **78 passed, 0 failed**.
