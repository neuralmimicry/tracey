# TraceyBan Practical Parity Checklist

## Target
Practical parity means TraceyBan can ingest real authentication failures from files or the systemd journal, match them with explicit fail regexes, apply and remove real firewall blocks, preserve state across restarts, and avoid banning trusted ranges or benign telemetry.

## Closed In This Change
- [x] File-backed log watching with persisted offsets and active-ban restore
- [x] `systemd`/journal-style ingestion via `journalctl` and `journalmatch` clauses
- [x] Strict failregex semantics for log and event inputs; no default IP-only fallback
- [x] Safer default jail regexes that require failure language plus an address
- [x] Safe argv-based action execution for common firewall commands
- [x] Shell fallback moved behind explicit `tracey_ban.allow_shell_actions`
- [x] CIDR-aware ignore lists in addition to exact IP ignores
- [x] Persisted ban counts, incremental ban windows, and randomized/max ban limits
- [x] Built-in Rust-native `filter_catalog` with hardened `sshd` / `sshd-aggressive` defaults
- [x] Built-in Rust-native `action_catalog` with `auto`, `ufw`, `firewalld`, and `nftables`
- [x] Automatic firewall backend selection that prefers active `firewalld` / `ufw` over raw `nft`
- [x] Manual ban, unban, and backend-refresh control via `/control/tracey_ban`
- [x] Enforcement safety: only record active bans when the firewall action succeeds; only clear bans when unban succeeds
- [x] Existing Tracey enhancements retained: fuzzy retry adjustment, remote corroboration, and discovery ban gossip

## Deployment Checklist
- [ ] Run Tracey as root or grant narrowly-scoped `sudo` access for the selected firewall commands
- [ ] Bind the status API to loopback or enable OIDC before exposing it
- [ ] Disable unused default-on subsystems if deploying primarily for ban enforcement
- [ ] Rotate `discovery.shared_key` and `update.shared_key`, or disable discovery/update paths
- [ ] Load a hardened jail config with real auth log paths and `action_catalog = auto`
- [ ] Test one known failed SSH login and confirm: detect -> ban -> persist -> unban
- [ ] Verify both file and journal paths on the target host; keep only the backend that actually emits data
- [ ] Confirm trusted management ranges are listed in `ignore_ips`
- [ ] Query `GET /tracey_ban` and confirm the resolved backend is the expected `ufw`, `firewalld`, or `nftables`
- [ ] Use `POST /control/tracey_ban` once to validate manual `ban` / `unban` and `refresh_backend`
- [ ] Review ban propagation if discovery is enabled; keep it disabled on single-node deployments

## Optional Next Steps For Broader Upstream Compatibility
- [ ] Add broader legacy filter macro/interpolation compatibility for imported filter files
- [x] Expand the built-in filter catalogue beyond SSH to common web/app auth surfaces
- [ ] Add hostname-based ignore resolution alongside exact IP and CIDR matching
- [ ] Add regression fixtures for common auth log formats and journal transcripts
