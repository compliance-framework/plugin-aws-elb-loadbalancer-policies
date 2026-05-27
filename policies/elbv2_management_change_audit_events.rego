package compliance_framework.elbv2_management_change_audit_events

# METADATA
# title: ELBv2 load balancer management changes are audited
# description: Checks whether listener and rule management changes are present, attributable, and timely when management audit enforcement is enabled.
# custom:
#   metric_ids:
#     - ELBV2_MANAGEMENT_CHANGE_AUDIT_EVENTS
#   controls:
#     - ctrl-cc6-2-015
#     - ctrl-cc6-2-019
#     - ctrl-cc6-3-013
#     - ctrl-cc6-7-018
risk_templates := [{
	"name": "Load balancer management changes are not auditable",
	"title": "Missing or Weak Management Audit Events Reduce Change Accountability",
	"statement": "Listener and rule changes without complete audit evidence can hide unauthorized or unreviewed modifications to traffic routing. Missing, unattributed, or stale change events reduce the ability to reconstruct management activity and confirm that operational changes followed the expected process.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-778",
		"title": "Insufficient Logging",
		"url": "https://cwe.mitre.org/data/definitions/778.html",
	}],
	"remediation": {
		"title": "Capture attributable and timely load balancer management audit events",
		"description": "Ensure CloudTrail records listener and rule management changes with user identity details and that change evidence is reviewed within the configured window.",
		"tasks": [
			{"title": "Enable and retain CloudTrail management events for ELBv2 listener and rule changes"},
			{"title": "Investigate listener or rule events missing user identity attribution"},
			{"title": "Review stale management change evidence and refresh the audit record"},
		],
	},
}]

dynamic := object.get(input, "dynamic", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", "unknown")
events := object.get(dynamic, "cloudtrail_events", [])
require_management_audit_events := data.require_management_audit_events
change_review_window_days := data.change_review_window_days
review_window_ns := (((change_review_window_days * 24) * 60) * 60) * 1000000000

now_ns := data.now if {
	is_number(data.now)
} else := time.now_ns()

management_event_names := {
	"AddListenerCertificates",
	"CreateListener",
	"CreateRule",
	"DeleteListener",
	"DeleteRule",
	"ModifyListener",
	"ModifyRule",
	"RemoveListenerCertificates",
	"SetRulePriorities",
}

management_events := [event |
	event := events[_]
	event_name := object.get(event, "event_name", "")
	event_name in management_event_names
]

event_times := [parsed |
	event := management_events[_]
	event_time := object.get(event, "event_time", "")
	parsed := time.parse_rfc3339_ns(event_time)
]

skip_reason := sprintf("Resource type %q is not a load balancer; this policy only applies to loadbalancer records.", [resource_type]) if {
	not resource_type == "loadbalancer"
}

title := sprintf("Validate ELBv2 management change audit events for %s", [resource_id])
description := sprintf("Load balancer %s has %d listener/rule management audit events; enforcement is %v.", [resource_id, count(management_events), require_management_audit_events])

unattributable_event_exists if {
	event := management_events[_]
	user_identity_arn := object.get(event, "user_identity_arn", "")
	trim(user_identity_arn, " \t\r\n") == ""
}

management_event_stale if {
	count(management_events) > 0
	count(event_times) == 0
}

management_event_stale if {
	count(event_times) > 0
	now_ns - max(event_times) > review_window_ns
}

violation contains {"id": "management_events_missing"} if {
	resource_type == "loadbalancer"
	require_management_audit_events
	count(management_events) == 0
}

violation contains {"id": "management_event_unattributable"} if {
	resource_type == "loadbalancer"
	require_management_audit_events
	unattributable_event_exists
}

violation contains {"id": "management_event_stale"} if {
	resource_type == "loadbalancer"
	require_management_audit_events
	count(management_events) > 0
	management_event_stale
}
