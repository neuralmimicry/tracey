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
Tracey shows a sustained worsening telemetry trend across 24 samples. Focus on the highest-pressure signals before the adaptive loop starts making poorer placement decisions. Current headline: network_queue_pressure=0.20 (worsening), forecast_15m_pressure=0.45 (stable), continuum_placement_score=0.61 (stable)

Authoritative delivery constraints (mandatory; implement and verify these, do not merely describe them):
- No structured delivery constraints were supplied; follow the work-item summary exactly.

Plan JSON:
{"action":"stabilize_tracey_trend","finding_id":"4c0436fe-dbba-4189-ae8f-b8ab709b9261","finding_key":"tracey_worsening_trend","headline":"tracey trend is worsening via network_queue_pressure (0.20 latest, 0.18 slope).","metrics":[{"average":0.21403897599309693,"direction":"worsening","latest":0.2033539650959336,"metric_name":"network_queue_pressure","slope":0.1779084383494023},{"average":0.5376267548839211,"direction":"stable","latest":0.45,"metric_name":"forecast_15m_pressure","slope":-0.02999999999999997},{"average":0.6441340881256167,"direction":"stable","latest":0.6060024021167181,"metric_name":"continuum_placement_score","slope":-0.006770432148813232},{"average":0.7505240867460525,"direction":"stable","latest":0.7132678370154916,"metric_name":"continuum_overall_score","slope":-0.005862334700411309},{"average":0.7907626575833823,"direction":"stable","latest":0.7672744519721089,"metric_name":"continuum_readiness_score","slope":-0.0054731500796674215},{"average":0.05000000000000002,"direction":"stable","latest":0.05,"metric_name":"capability_count","slope":0.0},{"average":0.040000000000000015,"direction":"stable","latest":0.04,"metric_name":"dependency_count","slope":0.0},{"average":0.0,"direction":"stable","latest":0.0,"metric_name":"health_severity","slope":0.0},{"average":0.8890833333333333,"direction":"stable","latest":1.0,"metric_name":"network_latency_pressure","slope":0.0},{"average":1.0,"direction":"stable","latest":1.0,"metric_name":"pressure_score","slope":0.0}],"sample_count":24}