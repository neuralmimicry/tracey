Overview: Improve Tracey through the Conductor execution loop.

Delivery Context:
- Current stage: development
- Validated stages: none
- Rollout strategy: canary

Requirements Register:
- REQ-001: Inspect and record current repository, runtime, or job evidence before selecting an operation.
- REQ-002: Implement only the scoped change, job update, or progress-monitoring action supported by that evidence.
- REQ-003: Preserve secure, resilient behaviour and avoid destructive commands.
- REQ-004: Update or add tests covering the changed path, or provide the relevant live operational check.
- REQ-005: Run verification commands and report the outcome.
- REQ-006: Leave unrelated files untouched.
- REQ-007: Record rollback/recovery steps and the acceptance signal proving the gap is closed.
- REQ-008: Preserve staged progression and rollout governance metadata.
- REQ-013: When runtime rollout or restart work is needed, use the available Ansible automation context: {"ansible_root":"/srv/swarmhpc/ansible","config_path":"/srv/swarmhpc/ansible/ansible.cfg","host_targets":["centriq2400","pi3b","rk1","sm_amd64","tracey"],"hosts":["cortex","n1sdp","qc00","qc01","qc02","qc03","qc04","qc05","sm00","sm01","spirit","vega"],"inventory_path":"/srv/swarmhpc/ansible/inventory/hosts.ini","playbooks":["pi3bsite.yml","rk1site.yml","tracey_site.yml"],"repo_root":"/srv/swarmhpc","roles_path":"/srv/swarmhpc/ansible/roles","secrets_root":"/srv/swarmhpc/ansible/.secrets"}.

Work Item Summary:
Tracey is surfacing elevated pressure or latency. Rebalance workloads, trim noisy loops, or increase capacity before the hotspot becomes a bottleneck.

Authoritative delivery constraints (mandatory; implement and verify these, do not merely describe them):
- No structured delivery constraints were supplied; follow the work-item summary exactly.

Plan JSON:
{"action":"investigate_resource_hotspot","finding_id":"a34ff546-b746-4455-a179-957f0cb7aa6c","finding_key":"tracey_pressure_hotspot","pressure_score":1.0}

Planner guidance (advisory; it must not weaken or contradict the authoritative work-item requirements):
Overview: This work item addresses a worsening Tracey telemetry trend (forecast_15m_pressure=0.96, placement_score declining) by validating the current runtime state, checking Ansible syntax, and preparing a canary rollout to confirm safe remediation.

Requirements Register:
- REQ-001: Inspect /srv/swarmhpc/ansible for path accessibility, current branch state, and any existing Tracey-related tests or incidents.
- REQ-002: Query the local K3s cluster via kubectl get nodes to confirm control-plane and worker connectivity.
- REQ-003: Review service health logs and metrics on host 'spirit' to identify the root cause of the worsening pressure trend.
- REQ-004: Execute ansible-playbook --syntax-check /srv/swarmhpc/ansible/playbooks/tracey_site.yml to validate syntax without applying changes.
- REQ-005: Run the tracey_site.yml playbook in dry-run mode to observe intended resource adjustments.
- REQ-006: Prepare a canary deployment plan that routes traffic to the adjusted configuration while retaining the previous version.
- REQ-007: Execute the canary rollout and verify improved pressure scores and placement stability over the next 15 minutes.
- REQ-008: Update runtime monitoring alerts to reflect the current pressure score and forecasted trajectory.
- REQ-009: Ensure no destructive changes are applied before runtime verification confirms safe behaviour.
- REQ-010: Document the specific resource adjustments, failed probes, or uncertainty in the delivery notes.

Rollout notes: The canary strategy allows safe validation of the adjusted configuration before full promotion. Monitor pressure_score and forecast_15m_pressure closely during the canary phase.
