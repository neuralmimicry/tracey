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
Tracey shows a sustained worsening telemetry trend across 24 samples. Focus on the highest-pressure signals before the adaptive loop starts making poorer placement decisions. Current headline: network_queue_pressure=0.30 (worsening), continuum_readiness_score=0.57 (worsening), continuum_overall_score=0.54 (worsening)

Authoritative delivery constraints (mandatory; implement and verify these, do not merely describe them):
- No structured delivery constraints were supplied; follow the work-item summary exactly.

Plan JSON:
{"action":"stabilize_tracey_trend","finding_id":"6d14246d-53d0-487c-9fa0-548d0fb03487","finding_key":"tracey_worsening_trend","headline":"tracey trend is worsening via network_queue_pressure (0.30 latest, 0.29 slope).","metrics":[{"average":0.32035930453876693,"direction":"worsening","latest":0.29877845476379694,"metric_name":"network_queue_pressure","slope":0.28689729097678396},{"average":0.7186071336689261,"direction":"worsening","latest":0.572327368249381,"metric_name":"continuum_readiness_score","slope":-0.16259940543028928},{"average":0.6525583749167451,"direction":"worsening","latest":0.5368342418789273,"metric_name":"continuum_overall_score","slope":-0.12419154506880692},{"average":0.5088612711616559,"direction":"worsening","latest":0.4061002803478684,"metric_name":"continuum_placement_score","slope":-0.10123987089201449},{"average":0.670724807814964,"direction":"worsening","latest":0.65,"metric_name":"forecast_15m_pressure","slope":0.04000000000000003},{"average":0.05000000000000002,"direction":"stable","latest":0.05,"metric_name":"capability_count","slope":0.0},{"average":0.040000000000000015,"direction":"stable","latest":0.04,"metric_name":"dependency_count","slope":0.0},{"average":0.0,"direction":"stable","latest":0.0,"metric_name":"health_severity","slope":0.0},{"average":1.0,"direction":"stable","latest":1.0,"metric_name":"network_latency_pressure","slope":0.0},{"average":1.0,"direction":"stable","latest":1.0,"metric_name":"pressure_score","slope":0.0}],"sample_count":24}