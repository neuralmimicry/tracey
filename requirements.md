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
Tracey depends on shared data services but no clear persistent-storage profile was inferred from Ansible. Confirm PVCs or durable mounts before further automation.

Authoritative delivery constraints (mandatory; implement and verify these, do not merely describe them):
- No structured delivery constraints were supplied; follow the work-item summary exactly.

Plan JSON:
{"action":"verify_persistent_storage","finding_id":"d7de14f3-db00-44cf-8b0b-194d08c16e07","finding_key":"storage_profile:tracey","service":"tracey"}

Planner guidance (advisory; it must not weaken or contradict the authoritative work-item requirements):
Overview: This work item verifies the persistent storage strategy for Tracey, which depends on shared data services but lacks a confirmed storage profile. The goal is to determine the storage medium, current state, and any runtime impact before further automation.

Requirements Register:
- REQ-001: Confirm Tracey's runtime state on host 'tracey' via kubectl describe and log review.
- REQ-002: Identify storage paths, volume names, or mount evidence from Ansible inventory and playbooks.
- REQ-003: Validate Ansible syntax and inventory using --check without applying changes.
- REQ-004: Assess cluster connectivity and node health to ensure safe inspection.
- REQ-005: Determine if evidence supports continued development or requires a no-change decision.
- REQ-006: Document uncertainty and recommended next steps in the verification summary.

Notes: 
- Tracey is linked to live services but currently lacks executable project-native validation.
- The inventory shows a dedicated tracey host, but no runtime probes, logs, or job traces indicate whether it uses a PVC, NFS, or in-memory storage.
- Before further automation, we must determine the storage medium, its current state, and any runtime impact.
- If evidence is insufficient, recommend a no-change decision and specify what additional data would close the gap.
