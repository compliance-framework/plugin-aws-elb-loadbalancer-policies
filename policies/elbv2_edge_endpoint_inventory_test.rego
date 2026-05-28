package compliance_framework.elbv2_edge_endpoint_inventory_test

test_internet_facing_inventory_ok if {
	inp := {
		"resource": {"type": "loadbalancer", "id": "lb-1"},
		"config": {"scheme": "internet-facing", "dns_name": "lb.example.elb.amazonaws.com"},
		"tags": {"owner": "platform"},
	}
	count(data.compliance_framework.elbv2_edge_endpoint_inventory.violation) == 0 with input as inp
}

test_missing_dns_violation if {
	inp := {
		"resource": {"type": "loadbalancer", "id": "lb-1"},
		"config": {"scheme": "internet-facing", "dns_name": ""},
		"tags": {"owner": "platform"},
	}
	data.compliance_framework.elbv2_edge_endpoint_inventory.violation[{"id": "dns_not_inventoried"}] with input as inp
}

test_missing_owner_violation if {
	inp := {
		"resource": {"type": "loadbalancer", "id": "lb-1"},
		"config": {"scheme": "internet-facing", "dns_name": "lb.example.elb.amazonaws.com"},
		"tags": {},
	}
	data.compliance_framework.elbv2_edge_endpoint_inventory.violation[{"id": "owner_not_identified"}] with input as inp
}

test_missing_dns_and_owner_returns_two_violations if {
	inp := {
		"resource": {"type": "loadbalancer", "id": "lb-1"},
		"config": {"scheme": "internet-facing", "dns_name": ""},
		"tags": {},
	}
	violations := data.compliance_framework.elbv2_edge_endpoint_inventory.violation with input as inp
	violations[{"id": "dns_not_inventoried"}]
	violations[{"id": "owner_not_identified"}]
	count(violations) == 2
}

test_internal_loadbalancer_skipped if {
	inp := {
		"resource": {"type": "loadbalancer", "id": "lb-1"},
		"config": {"scheme": "internal"},
	}
	count(data.compliance_framework.elbv2_edge_endpoint_inventory.violation) == 0 with input as inp
	data.compliance_framework.elbv2_edge_endpoint_inventory.skip_reason with input as inp
}

test_missing_scheme_violation if {
	inp := {
		"resource": {"type": "loadbalancer", "id": "lb-1"},
		"config": {},
	}
	data.compliance_framework.elbv2_edge_endpoint_inventory.violation[{"id": "scheme_unknown"}] with input as inp
}

test_unexpected_scheme_violation if {
	inp := {
		"resource": {"type": "loadbalancer", "id": "lb-1"},
		"config": {"scheme": "private"},
	}
	data.compliance_framework.elbv2_edge_endpoint_inventory.violation[{"id": "scheme_unknown"}] with input as inp
}

test_unknown_scheme_can_be_configured_to_skip if {
	inp := {
		"resource": {"type": "loadbalancer", "id": "lb-1"},
		"config": {"scheme": "private"},
	}
	count(data.compliance_framework.elbv2_edge_endpoint_inventory.violation) == 0 with input as inp with data.unknown_endpoint_scheme_action as "skip"
	data.compliance_framework.elbv2_edge_endpoint_inventory.skip_reason with input as inp with data.unknown_endpoint_scheme_action as "skip"
}

test_non_default_owner_key if {
	inp := {
		"resource": {"type": "loadbalancer", "id": "lb-1"},
		"config": {"scheme": "internet-facing", "dns_name": "lb.example.elb.amazonaws.com"},
		"tags": {"service-owner": "platform"},
	}
	count(data.compliance_framework.elbv2_edge_endpoint_inventory.violation) == 0 with input as inp with data.required_owner_tag_keys as ["service-owner"]
}

test_non_loadbalancer_record_skipped if {
	inp := {"resource": {"type": "listener", "id": "l-1"}}
	count(data.compliance_framework.elbv2_edge_endpoint_inventory.violation) == 0 with input as inp
	data.compliance_framework.elbv2_edge_endpoint_inventory.skip_reason with input as inp
}
