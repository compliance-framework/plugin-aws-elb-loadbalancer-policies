package compliance_framework.elbv2_edge_endpoint_inventory

# METADATA
# title: ELBv2 internet-facing load balancer is inventoried
# description: Checks whether an externally reachable load balancer has DNS inventory evidence and ownership metadata.
# custom:
#   metric_ids:
#     - EDGE_ENDPOINT_INVENTORY
#   controls:
#     - ctrl-cc5-2-005
risk_templates := [{
	"name": "Internet-facing load balancer is not inventoried",
	"title": "Uninventoried Edge Load Balancer Weakens Exposure Management",
	"statement": "An internet-facing load balancer without DNS and ownership inventory can be missed during exposure reviews, incident response, and control validation. Unknown or unowned edge endpoints increase the chance that externally reachable services remain misconfigured or unmanaged.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-1059",
		"title": "Insufficient Technical Documentation",
		"url": "https://cwe.mitre.org/data/definitions/1059.html",
	}],
	"remediation": {
		"title": "Inventory externally reachable load balancer endpoints",
		"description": "Record the load balancer DNS name and owner in endpoint inventory so the externally reachable surface can be reviewed and governed.",
		"tasks": [
			{"title": "Confirm the internet-facing load balancer has a DNS name in evidence"},
			{"title": "Add an approved owner or team tag to the load balancer"},
		],
	},
}]

config := object.get(input, "config", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", "unknown")
scheme := object.get(config, "scheme", "")
dns_name := object.get(config, "dns_name", "")
tags := object.get(input, "tags", {})
required_owner_tag_keys := data.required_owner_tag_keys
unknown_endpoint_scheme_action := data.unknown_endpoint_scheme_action

skip_reason := sprintf("Resource type %q is not a load balancer; this policy only applies to loadbalancer records.", [resource_type]) if {
	not resource_type == "loadbalancer"
} else := sprintf("Load balancer %s is internal; edge endpoint inventory applies only to internet-facing load balancers.", [resource_id]) if {
	resource_type == "loadbalancer"
	scheme == "internal"
} else := sprintf("Load balancer %s has unknown scheme %q; edge endpoint inventory applies only when the scheme is known.", [resource_id, scheme]) if {
	resource_type == "loadbalancer"
	unknown_scheme
	unknown_endpoint_scheme_action == "skip"
}

title := sprintf("Validate ELBv2 edge endpoint inventory for %s", [resource_id])
description := sprintf("Internet-facing load balancer %s must have a DNS name and one of the required ownership tags: %v.", [resource_id, required_owner_tag_keys])

owner_tag_present if {
	some key in required_owner_tag_keys
	value := object.get(tags, key, "")
	trim(value, " \t\r\n") != ""
}

dns_name_present if {
	trim(dns_name, " \t\r\n") != ""
}

unknown_scheme if {
	not scheme == "internet-facing"
	not scheme == "internal"
}

violation contains {"id": "dns_not_inventoried"} if {
	resource_type == "loadbalancer"
	scheme == "internet-facing"
	not dns_name_present
}

violation contains {"id": "owner_not_identified"} if {
	resource_type == "loadbalancer"
	scheme == "internet-facing"
	not owner_tag_present
}

violation contains {"id": "scheme_unknown"} if {
	resource_type == "loadbalancer"
	unknown_scheme
	not unknown_endpoint_scheme_action == "skip"
}
