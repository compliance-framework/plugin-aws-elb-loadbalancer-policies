package compliance_framework.elbv2_asset_disposal_test

test_gate_false_never_fails if {
	inp := {"resource": {"type": "loadbalancer", "id": "lb-1"}, "config": {"state": "failed"}}
	count(data.compliance_framework.elbv2_asset_disposal.violation) == 0 with input as inp
}

test_active_state_ok_when_gate_true if {
	inp := {"resource": {"type": "loadbalancer", "id": "lb-1"}, "config": {"state": "active"}}
	count(data.compliance_framework.elbv2_asset_disposal.violation) == 0 with input as inp with data.require_disposal_audit_events as true
}

test_failed_state_with_delete_event_ok if {
	inp := {
		"resource": {"type": "loadbalancer", "id": "lb-1"},
		"config": {"state": "failed"},
		"dynamic": {"cloudtrail_events": [{"event_name": "DeleteLoadBalancer"}]},
	}
	count(data.compliance_framework.elbv2_asset_disposal.violation) == 0 with input as inp with data.require_disposal_audit_events as true
}

test_failed_state_without_delete_event_violation if {
	inp := {
		"resource": {"type": "loadbalancer", "id": "lb-1"},
		"config": {"state": "failed"},
		"dynamic": {"cloudtrail_events": [{"event_name": "ModifyLoadBalancerAttributes"}]},
	}
	count(data.compliance_framework.elbv2_asset_disposal.violation) == 1 with input as inp with data.require_disposal_audit_events as true
}

test_non_loadbalancer_record_skipped if {
	inp := {"resource": {"type": "listener", "id": "l-1"}}
	count(data.compliance_framework.elbv2_asset_disposal.violation) == 0 with input as inp with data.require_disposal_audit_events as true
	data.compliance_framework.elbv2_asset_disposal.skip_reason with input as inp
}
