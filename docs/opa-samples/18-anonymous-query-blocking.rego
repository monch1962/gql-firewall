# Sample 18: anonymous-query-blocking.rego
# Topic: Require named operations
#
# WHY: Named operations (query GetUser { ... }) are easier to audit,
# log, and allowlist than anonymous operations ({ ... }). In production,
# requiring named operations:
#   - Makes logs actionable (you see "query GetUser" not "anonymous")
#   - Enables operation-name-based rate limiting
#   - Prevents ad-hoc queries from development tools (GraphiQL, Altair)
#   - Forces API clients to declare their intent
#
# DEFENCE: Block requests where operation_name is empty.
#
# PARAM: input.params.allow_anonymous (boolean, default false)
#   When true, anonymous queries pass through. Use this for development
#   environments or public APIs that serve anonymous users.

package graphql

default allow := false

allow if {
    count(deny) == 0
}

deny contains "anonymous queries are not allowed" if {
    input.operation_name == ""
    not input.params.allow_anonymous
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_named_query_allowed if {
    allow with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["hello"], "operation_name": "GetHello",
        "params": {}
    }
}

test_anonymous_blocked if {
    deny["anonymous queries are not allowed"] with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["hello"], "operation_name": "",
        "params": {}
    }
}

test_anonymous_allowed_when_param_set if {
    allow with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["hello"], "operation_name": "",
        "params": {"allow_anonymous": true}
    }
}
