# Sample 02: input-document-assertions.rego
# Topic: Understanding what input looks like
#
# Before writing deny rules, you need to understand what data the firewall
# sends to OPA. This sample verifies that all input fields are present and
# have the expected types. Use this as a debugging tool: if your policy
# isn't working, copy this file and run "opa test" to see what the firewall
# actually sends.
#
# INPUT FIELDS (populated by the Go sidecar):
#   operation_type    string   — "query|mutation|subscription"
#   operation_name    string   — named operation or ""
#   depth             number   — max nesting depth
#   field_count       number   — total fields requested
#   field_paths       array    — dot-separated field paths
#   tenant_id         string   — from X-API-Key header
#   directives        number   — total @directives
#   batch_size        number   — operations in this request
#   argument_depth    number   — max arg nesting
#   lists_requested   number   — plural-field count (heuristic)
#   fragment_spread_count  number — fragment/inline spread count
#   query_hash        string   — SHA-256 prefix
#   params            object   — configuration
#   tenant_config     object   — per-tenant overrides (may be null)
#
# See: tutorial.md → "The Input document"

package graphql

default allow := false

allow if {
    count(deny) == 0
}

# Verify operation_type is present and valid
deny contains "missing operation_type" if {
    not input.operation_type
}

deny contains "invalid operation_type" if {
    input.operation_type
    not input.operation_type == "query"
    not input.operation_type == "mutation"
    not input.operation_type == "subscription"
}

# Verify depth is a non-negative number
deny contains "invalid depth" if {
    input.depth < 0
}

# Verify field_count is positive
deny contains "invalid field_count" if {
    input.field_count < 1
}

# Verify field_paths is a non-empty array
deny contains "missing field_paths" if {
    count(input.field_paths) == 0
}

# Verify params object exists (even if empty)
deny contains "missing params" if {
    input.params == null
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_all_fields_provided if {
    allow with input as {
        "depth": 3, "field_count": 5, "operation_type": "query",
        "operation_name": "GetUser", "field_paths": ["user", "user.name"],
        "directives": 0, "batch_size": 1, "argument_depth": 0,
        "lists_requested": 1, "fragment_spread_count": 0, "query_hash": "",
        "tenant_id": "", "params": {"depth_limit": 10},
        "tenant_config": null
    }
}
