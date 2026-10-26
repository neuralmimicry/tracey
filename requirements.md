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
Tracey shows a sustained worsening telemetry trend across 24 samples. Focus on the highest-pressure signals before the adaptive loop starts making poorer placement decisions. Current headline: network_latency_pressure=1.00 (worsening), forecast_15m_pressure=0.51 (improving), continuum_overall_score=0.78 (worsening)

Authoritative delivery constraints (mandatory; implement and verify these, do not merely describe them):
- No structured delivery constraints were supplied; follow the work-item summary exactly.

Plan JSON:
{"action":"stabilize_tracey_trend","finding_id":"92f49249-94ea-44e5-88e8-be7f1620ea62","finding_key":"tracey_worsening_trend","headline":"tracey trend is worsening via network_latency_pressure (1.00 latest, 0.51 slope).","metrics":[{"average":0.6075833333333333,"direction":"worsening","latest":1.0,"metric_name":"network_latency_pressure","slope":0.506},{"average":0.6865761436682831,"direction":"improving","latest":0.51,"metric_name":"forecast_15m_pressure","slope":-0.17000000000000004},{"average":0.8141389517438644,"direction":"worsening","latest":0.7827800351669265,"metric_name":"continuum_overall_score","slope":-0.0842815198592336},{"average":0.7189577644902504,"direction":"worsening","latest":0.701668717575162,"metric_name":"continuum_placement_score","slope":-0.057836601131183496},{"average":0.8120737462811277,"direction":"worsening","latest":0.8255777427062541,"metric_name":"continuum_readiness_score","slope":-0.03132934217125505},{"average":0.06889306098945565,"direction":"stable","latest":0.0032414246475473587,"metric_name":"network_queue_pressure","slope":0.0032414246475473587},{"average":0.05000000000000002,"direction":"stable","latest":0.05,"metric_name":"capability_count","slope":0.0},{"average":0.040000000000000015,"direction":"stable","latest":0.04,"metric_name":"dependency_count","slope":0.0},{"average":0.0,"direction":"stable","latest":0.0,"metric_name":"health_severity","slope":0.0},{"average":1.0,"direction":"stable","latest":1.0,"metric_name":"pressure_score","slope":0.0}],"sample_count":24}