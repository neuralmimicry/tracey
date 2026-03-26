# Tracey Workflow Analysis and Enhancements

## Current Workflow (Before This Change)
1. Sensors/collectors publish events to a broadcast event bus.
2. Swarm agents score events (adaptive baseline + Type-n fuzzy telemetry).
3. Coordinators aggregate assessments and issue decisions.
4. Governance and coordination adjust posture/thresholds and leader roles.
5. Discovery gossips authenticated agent presence.
6. Storage writes JSONL records for long-lived auditing.

## Bottlenecks / Gaps Identified
1. No native log-ban lifecycle engine comparable to Fail2Ban jails/filters/actions.
2. Ban state was not propagated between agents, so each node decided in isolation.
3. Status endpoint did not expose ban posture and peer ban context.
4. No persistent ban + offset continuity for restart-safe ban behavior.

## Enhancements Implemented
1. Added a Rust-native Fail2Ban subsystem (`src/fail2ban.rs`) with:
   - Multi-jail runtime.
   - Log polling backend and event backend (plus hybrid mode).
   - Fail/ignore regex matching.
   - Optional ingestion of Fail2Ban filter files (`[Definition] failregex/ignoreregex`).
   - Ban manager with find-time/max-retry/bantime/incremental bans.
   - Start/stop/ban/unban shell action hooks.
   - Persistent local state (active bans + offsets + ban counters).
   - Full Tracey fuzzy integration (Type-n `AdaptiveScorer`) with fuzzy risk/confidence telemetry and fuzzy-adjusted retry thresholds.
   - Privilege-aware operation: root requirement detection, optional sudo auto-elevation, and permission-issue logging for protected log paths/firewall updates.
2. Added distributed ban-intel hub:
   - Local ban updates are published to shared in-memory state.
   - Discovery announcements now include signed ban advertisements.
   - Remote ban intel is consumed and merged per peer.
   - Local ban threshold is lowered when peers already ban the same IP (consensus-assisted banning).
3. Extended status plane:
   - Status response now includes local/remote ban counts, remote agent count, and sample entries.
4. Extended storage plane:
   - Added explicit `ban_update` records in JSONL stream.
   - Added bounded log rotation/pruning (`rotate_archives`) plus a total byte budget (`max_total_bytes`) to cap disk usage and avoid expensive full-file rewrite compaction under sustained load.

## Parallelism / Duplication Strategy
1. Kept existing Tracey concurrency model (Tokio tasks + channels).
2. Spawned jail workers in parallel per backend and log source.
3. Reused existing discovery/status/storage paths instead of creating separate transport stacks.
4. Reused shared event bus and governance surface, avoiding duplicate event infrastructure.

## Operational Notes
1. Fail2Ban action commands are optional; default config performs logical bans and intel sharing without mutating firewall state.
2. To enforce network bans, set `action_ban` and `action_unban` per jail.
3. Discovery signatures now cover ban advertisement payload hash to preserve authenticity.
