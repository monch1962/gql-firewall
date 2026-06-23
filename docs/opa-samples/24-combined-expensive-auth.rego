# Sample 24: combined-expensive-auth.rego
# Topic: Intersection — expensive field + tenant check
#
# RATIONALE: Expensive fields (exportData, generateReport, sendEmail) should
# only be accessible to authorised tenants (premium plans). Instead of
# duplicating the blocklist per tenant, this policy uses a SINGLE list of
# expensive fields and checks the requesting tenant's plan tier.
#
# PATTERN: Join a field blocklist with a tenant config check.
# If the field is in the expensive list AND the tenant's plan_tier is
# not "premium", block the request.
#
# This is more flexible than a flat blocklist because it allows:
#   - Free tier: blocked from all expensive fields
#   - Pro tier: blocked from some expensive fields
#   - Enterprise: no restrictions
#
# PARAM: input.params.expensive_fields (array of strings — field paths)
# PARAM: input.params.required_plan (string, default "premium")

package graphql

default allow := false

allow if {
    count(deny) == 0
}

deny contains msg if {
    input.tenant_config
    input.tenant_config.plan_tier
    some expensive in input.params.expensive_fields
    some path in input.field_paths
    path == expensive
    input.tenant_config.plan_tier != "premium"
    msg := sprintf("field %q requires premium plan (current: %s)", [path, input.tenant_config.plan_tier])
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_premium_tenant_expensive_field_allowed if {
    allow with input as {
        "depth": 2, "field_count": 2, "operation_type": "query",
        "field_paths": ["export", "export.data"],
        "tenant_id": "bigcorp",
        "params": {"expensive_fields": ["export.data"]},
        "tenant_config": {"plan_tier": "premium"}
    }
}

test_free_tenant_expensive_field_blocked if {
    some msg in deny with input as {
        "depth": 2, "field_count": 2, "operation_type": "query",
        "field_paths": ["export", "export.data"],
        "tenant_id": "freeuser",
        "params": {"expensive_fields": ["export.data"]},
        "tenant_config": {"plan_tier": "free"}
    }
    startswith(msg, "field \"export.data\" requires premium plan")
}
