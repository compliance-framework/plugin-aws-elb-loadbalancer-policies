package compliance_framework.elbv2_ownership_tags

# METADATA
# title: ELBv2 load balancer has ownership tags
# description: Checks whether a load balancer has a required non-empty ownership tag.
# custom:
#   metric_ids:
#     - ACM_TLS_ENDPOINTS
#   controls:
#     - ctrl-cc6-7-017
risk_templates := [{
	"name": "Load balancer ownership is not identified",
	"title": "Missing Ownership Tags Delay Accountability for Load Balancers",
	"statement": "A load balancer without ownership tags may not have a responsible team for operational review, incident response, or remediation. Missing ownership metadata weakens asset governance and can allow exposed or misconfigured endpoints to persist without clear accountability.",
	"likelihood_hint": "medium",
	"impact_hint": "medium",
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-1059",
		"title": "Insufficient Technical Documentation",
		"url": "https://cwe.mitre.org/data/definitions/1059.html",
	}],
	"remediation": {
		"title": "Tag load balancers with an accountable owner",
		"description": "Apply at least one approved ownership tag with a non-empty value so the load balancer can be assigned to the right team or service owner.",
		"tasks": [
			{"title": "Add an approved owner or team tag to the load balancer"},
			{"title": "Confirm ownership values are kept current in inventory"},
		],
	},
}]

resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", "unknown")
tags := object.get(input, "tags", {})
required_owner_tag_keys := data.required_owner_tag_keys

skip_reason := sprintf("Resource type %q is not a load balancer; this policy only applies to loadbalancer records.", [resource_type]) if {
	not resource_type == "loadbalancer"
}

title := sprintf("Validate ELBv2 ownership tags for %s", [resource_id])
description := sprintf("Load balancer %s must have one of the required ownership tags: %v.", [resource_id, required_owner_tag_keys])

owner_tag_present if {
	some key in required_owner_tag_keys
	value := object.get(tags, key, "")
	trim(value, " \t\r\n") != ""
}

violation contains {"id": "owner_tags_missing"} if {
	resource_type == "loadbalancer"
	not owner_tag_present
}
