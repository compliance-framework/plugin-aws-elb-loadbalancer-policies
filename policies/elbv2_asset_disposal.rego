package compliance_framework.elbv2_asset_disposal

# METADATA
# title: ELBv2 load balancer disposal is auditable
# description: Checks whether non-active load balancers have deletion audit evidence when disposal audit enforcement is enabled.
# custom:
#   metric_ids:
#     - ELBV2_ASSET_DISPOSAL
#   controls:
#     - ctrl-cc6-5-001
#     - ctrl-cc6-7-003
#     - ctrl-cc6-7-006
risk_templates := [{
	"name": "Load balancer disposal process is unverified",
	"title": "Missing Disposal Audit Evidence Leaves Load Balancer Lifecycle Unverified",
	"statement": "A load balancer in a failed or otherwise inactive state without deletion audit evidence may indicate an incomplete disposal workflow. Unverified disposal can leave stale endpoints, configuration, or dependencies outside normal operational oversight.",
	"likelihood_hint": "low",
	"impact_hint": "medium",
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-1059",
		"title": "Insufficient Technical Documentation",
		"url": "https://cwe.mitre.org/data/definitions/1059.html",
	}],
	"remediation": {
		"title": "Verify load balancer disposal through audit events",
		"description": "Confirm inactive or failed load balancers have corresponding deletion events or complete the disposal workflow before removing inventory records.",
		"tasks": [
			{"title": "Review CloudTrail for the load balancer deletion event"},
			{"title": "Complete or document the disposal process for stale load balancers"},
		],
	},
}]

config := object.get(input, "config", {})
dynamic := object.get(input, "dynamic", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", "unknown")
state := object.get(config, "state", "")
events := object.get(dynamic, "cloudtrail_events", [])
require_disposal_audit_events := data.require_disposal_audit_events
disposal_delete_event_names := data.disposal_delete_event_names

skip_reason := sprintf("Resource type %q is not a load balancer; this policy only applies to loadbalancer records.", [resource_type]) if {
	not resource_type == "loadbalancer"
}

title := sprintf("Validate ELBv2 asset disposal audit evidence for %s", [resource_id])
description := sprintf("Load balancer %s is in state %q; disposal audit enforcement is %v.", [resource_id, state, require_disposal_audit_events])

active_or_provisioning_state if {
	state in {"active", "provisioning"}
}

delete_event_exists if {
	event := events[_]
	event_name := object.get(event, "event_name", "")
	event_name in disposal_delete_event_names
}

violation contains {"id": "disposal_process_unverified"} if {
	resource_type == "loadbalancer"
	require_disposal_audit_events
	not active_or_provisioning_state
	not delete_event_exists
}
