# Sample 19: tenant-isolation.rego
# Topic: Per-tenant policy overrides
#
# WHAT: When a request includes the X-API-Key header, the firewall extracts
# a tenant ID (everything before the last underscore) and populates
# input.tenant_config with that tenant's configuration from the data store.
#
# This lets you enforce DIFFERENT rules for different tenants without
# deploying separate firewall instances:
#   - Tenant A (gold plan): depth_limit=10
#   - Tenant B (free tier): depth_limit=3
#   - Tenant C (regulated): field_blocklist includes PII fields
#
# THE GUARD PATTERN (critical):
#   input.tenant_config              ← check that config exists
#   input.tenant_config.depth_limit  ← check the specific field exists
#   input.depth > input.tenant_config.depth_limit  ← apply the rule
#
# Each guard prevents Rego evaluation errors when the field is undefined.
# Without the first guard, a request without X-API-Key would cause an
# error on "input.tenant_config.depth_limit".
#
# SETTING TENANT CONFIG:
#   curl -X PUT http://localhost:8082/admin/tenants/acmecorp \
#     -H "Content-Type: application/json" \
#     -d '{"depth_limit": 3}'

package graphql

default allow := false

allow if {
    count(deny) == 0
}

# Tenant-specific depth limit
deny contains msg if {
    input.tenant_config
    input.tenant_config.depth_limit
    input.depth > input.tenant_config.depth_limit
    msg := sprintf("tenant depth limit %v exceeded", [input.tenant_config.depth_limit])
}

# Tenant-specific field blocklist
deny contains msg if {
    input.tenant_config
    some blocked in input.tenant_config.field_blocklist
    some path in input.field_paths
    path == blocked
    msg := sprintf("field %q is blocked by tenant policy", [path])
}

# Tenant-specific operation type blocking
deny contains msg if {
    input.tenant_config
    some blocked in input.tenant_config.blocked_operations
    input.operation_type == blocked
    msg := sprintf("operation type %q is blocked by tenant policy", [input.operation_type])
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_tenant_tight_depth_limit if {
    # Tenant with depth_limit=3 blocks a depth-5 query
    some msg in deny with input as {
        "depth": 5, "field_count": 3, "operation_type": "query",
        "field_paths": ["a", "a.b", "a.b.c"],
        "tenant_id": "strictcorp",
        "params": {"depth_limit": 10},
        "tenant_config": {"depth_limit": 3}
    }
    msg == "tenant depth limit 3 exceeded"
}

test_non_tenant_uses_global_limit if {
    # No tenant_id → no tenant_config → global params apply
    allow with input as {
        "depth": 5, "field_count": 3, "operation_type": "query",
        "field_paths": ["a", "a.b", "a.b.c"],
        "tenant_id": "",
        "params": {"depth_limit": 10},
        "tenant_config": null
    }
}

test_tenant_field_blocklist if {
    some msg in deny with input as {
        "depth": 2, "field_count": 2, "operation_type": "query",
        "field_paths": ["report", "report.ssn"],
        "tenant_id": "regulatedcorp",
        "params": {},
        "tenant_config": {"field_blocklist": ["report.ssn"]}
    }
    msg == "field \"report.ssn\" is blocked by tenant policy"
}
