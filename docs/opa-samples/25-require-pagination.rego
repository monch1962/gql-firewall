# Sample 25: require-pagination.rego
# Topic: Force pagination on list fields
#
# RATIONALE: List fields without pagination arguments can return thousands
# of records in a single response, causing:
#   - Memory pressure on the server (building a massive response)
#   - Network amplification (DoS via response size)
#   - Data exfiltration (attacker requests all users in one call)
#
# DEFENCE: When a query requests a list field, check that the field also
# has pagination arguments (first, last, limit, page, offset). If a list
# field is missing pagination, block the request.
#
# NOTE: This is a SCHEMA-LEVEL check — the firewall cannot inspect the
# arguments of a specific field using only the field_paths array. You
# need the Go sidecar to pass argument information (e.g., which fields
# have pagination args) or use the --schema flag for SDL-level validation.
#
# ALTERNATIVE: Use the list-field limiter (sample 14) to cap the NUMBER
# of list fields requested. This is a simpler approximation.
#
# ADVANCED: Combine with argument_depth (sample 13) — list fields that
# have flat arguments (no pagination args) are suspicious.
#
# This sample demonstrates the PATTERN using input.params as a bridge.
# In production, you'd populate has_pagination from the parser.

package graphql

default allow := false

allow if {
    count(deny) == 0
}

deny contains msg if {
    some list_field in input.params.require_pagination_for
    some path in input.field_paths
    endswith(path, list_field)
    not input.tenant_config
    msg := sprintf("field %q requires pagination arguments (first/last/offset)", [list_field])
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_list_field_without_pagination if {
    some msg in deny with input as {
        "depth": 2, "field_count": 2, "operation_type": "query",
        "field_paths": ["users", "users.name"],
        "params": {"require_pagination_for": ["users", "posts", "comments"]},
        "tenant_config": null
    }
    msg == "field \"users\" requires pagination arguments (first/last/offset)"
}

test_non_list_field_not_affected if {
    allow with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["user.name"],
        "params": {"require_pagination_for": ["users", "posts"]},
        "tenant_config": null
    }
}
