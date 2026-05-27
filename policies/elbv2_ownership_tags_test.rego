package compliance_framework.elbv2_ownership_tags_test

test_owner_tag_ok if {
	inp := {"resource": {"type": "loadbalancer", "id": "lb-1"}, "tags": {"owner": "platform"}}
	count(data.compliance_framework.elbv2_ownership_tags.violation) == 0 with input as inp
}

test_team_tag_ok if {
	inp := {"resource": {"type": "loadbalancer", "id": "lb-1"}, "tags": {"team": "edge"}}
	count(data.compliance_framework.elbv2_ownership_tags.violation) == 0 with input as inp
}

test_empty_owner_tag_violation if {
	inp := {"resource": {"type": "loadbalancer", "id": "lb-1"}, "tags": {"owner": "  "}}
	count(data.compliance_framework.elbv2_ownership_tags.violation) == 1 with input as inp
}

test_non_default_owner_key if {
	inp := {"resource": {"type": "loadbalancer", "id": "lb-1"}, "tags": {"service-owner": "platform"}}
	count(data.compliance_framework.elbv2_ownership_tags.violation) == 0 with input as inp with data.required_owner_tag_keys as ["service-owner"]
}

test_non_loadbalancer_record_skipped if {
	inp := {"resource": {"type": "listener", "id": "l-1"}}
	count(data.compliance_framework.elbv2_ownership_tags.violation) == 0 with input as inp
	data.compliance_framework.elbv2_ownership_tags.skip_reason with input as inp
}
