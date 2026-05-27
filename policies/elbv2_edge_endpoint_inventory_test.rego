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
	count(data.compliance_framework.elbv2_edge_endpoint_inventory.violation) == 1 with input as inp
}

test_missing_owner_violation if {
	inp := {
		"resource": {"type": "loadbalancer", "id": "lb-1"},
		"config": {"scheme": "internet-facing", "dns_name": "lb.example.elb.amazonaws.com"},
		"tags": {},
	}
	count(data.compliance_framework.elbv2_edge_endpoint_inventory.violation) == 1 with input as inp
}

test_internal_loadbalancer_skipped if {
	inp := {
		"resource": {"type": "loadbalancer", "id": "lb-1"},
		"config": {"scheme": "internal"},
	}
	count(data.compliance_framework.elbv2_edge_endpoint_inventory.violation) == 0 with input as inp
	data.compliance_framework.elbv2_edge_endpoint_inventory.skip_reason with input as inp
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
