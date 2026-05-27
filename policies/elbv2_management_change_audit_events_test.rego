package compliance_framework.elbv2_management_change_audit_events_test

test_gate_false_never_fails if {
	inp := {"resource": {"type": "loadbalancer", "id": "lb-1"}}
	count(data.compliance_framework.elbv2_management_change_audit_events.violation) == 0 with input as inp
}

test_management_events_ok_when_gate_true if {
	inp := {
		"resource": {"type": "loadbalancer", "id": "lb-1"},
		"dynamic": {"cloudtrail_events": [{
			"event_name": "ModifyListener",
			"event_time": "2026-05-01T00:00:00Z",
			"user_identity_arn": "arn:aws:iam::123456789012:role/admin",
		}]},
	}
	count(data.compliance_framework.elbv2_management_change_audit_events.violation) == 0 with input as inp with data.require_management_audit_events as true with data.now as time.parse_rfc3339_ns("2026-05-27T00:00:00Z")
}

test_management_events_missing_violation if {
	inp := {"resource": {"type": "loadbalancer", "id": "lb-1"}, "dynamic": {"cloudtrail_events": []}}
	count(data.compliance_framework.elbv2_management_change_audit_events.violation) == 1 with input as inp with data.require_management_audit_events as true
	data.compliance_framework.elbv2_management_change_audit_events.violation[{"id": "management_events_missing"}] with input as inp with data.require_management_audit_events as true
}

test_management_event_unattributable_violation if {
	inp := {
		"resource": {"type": "loadbalancer", "id": "lb-1"},
		"dynamic": {"cloudtrail_events": [{
			"event_name": "ModifyRule",
			"event_time": "2026-05-01T00:00:00Z",
			"user_identity_arn": "",
		}]},
	}
	data.compliance_framework.elbv2_management_change_audit_events.violation[{"id": "management_event_unattributable"}] with input as inp with data.require_management_audit_events as true with data.now as time.parse_rfc3339_ns("2026-05-27T00:00:00Z")
}

test_management_event_stale_violation if {
	inp := {
		"resource": {"type": "loadbalancer", "id": "lb-1"},
		"dynamic": {"cloudtrail_events": [{
			"event_name": "ModifyListener",
			"event_time": "2026-01-01T00:00:00Z",
			"user_identity_arn": "arn:aws:iam::123456789012:role/admin",
		}]},
	}
	data.compliance_framework.elbv2_management_change_audit_events.violation[{"id": "management_event_stale"}] with input as inp with data.require_management_audit_events as true with data.now as time.parse_rfc3339_ns("2026-05-27T00:00:00Z")
}

test_management_event_with_malformed_timestamp_stale if {
	inp := {
		"resource": {"type": "loadbalancer", "id": "lb-1"},
		"dynamic": {"cloudtrail_events": [{
			"event_name": "ModifyListener",
			"event_time": "not-a-valid-timestamp",
			"user_identity_arn": "arn:aws:iam::123456789012:role/admin",
		}]},
	}
	data.compliance_framework.elbv2_management_change_audit_events.violation[{"id": "management_event_stale"}] with input as inp with data.require_management_audit_events as true with data.now as time.parse_rfc3339_ns("2026-05-27T00:00:00Z")
}

test_non_default_review_window if {
	inp := {
		"resource": {"type": "loadbalancer", "id": "lb-1"},
		"dynamic": {"cloudtrail_events": [{
			"event_name": "ModifyListener",
			"event_time": "2026-05-01T00:00:00Z",
			"user_identity_arn": "arn:aws:iam::123456789012:role/admin",
		}]},
	}
	data.compliance_framework.elbv2_management_change_audit_events.violation[{"id": "management_event_stale"}] with input as inp with data.require_management_audit_events as true with data.change_review_window_days as 7 with data.now as time.parse_rfc3339_ns("2026-05-27T00:00:00Z")
}

test_non_loadbalancer_record_skipped if {
	inp := {"resource": {"type": "listener", "id": "l-1"}}
	count(data.compliance_framework.elbv2_management_change_audit_events.violation) == 0 with input as inp with data.require_management_audit_events as true
	data.compliance_framework.elbv2_management_change_audit_events.skip_reason with input as inp
}
