# Sample 05: depth-limit.rego
# Topic: Maximum query nesting depth
# OWASP: API4 — Mass Assignment
#
# ATTACK: An attacker sends { a { b { c { d { e { f } } } } } } to exhaust
# CPU/memory as the server resolves each nesting level. 8-10 levels is often
# enough to cause measurable load; 20+ can crash resolvers.
#
# DEFENCE: Count the nesting depth of field selections. Block when the count
# exceeds a threshold. The threshold should reflect your schema's real depth:
#   - Schema with User → Posts → Comments → Author → Posts → ... = 5-6 is
#     legitimate
#   - Flat schemas (User, Product, Order) = 3-4 is reasonable
#   - Admin introspection might need 10+
#
# PARAM: input.params.depth_limit (number, default 10)
#
# See: tutorial.md → Example 6 (combined deep-mutations)

package graphql

default allow := false

allow if {
    count(deny) == 0
}

deny contains msg if {
    input.depth > input.params.depth_limit
    msg := sprintf("query depth %d exceeds limit %v", [input.depth, input.params.depth_limit])
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_depth_under_limit_allowed if {
    allow with input as {
        "depth": 5, "field_count": 3, "operation_type": "query",
        "field_paths": ["a", "a.b", "a.b.c"],
        "params": {"depth_limit": 10}
    }
}

test_depth_at_limit_allowed if {
    allow with input as {
        "depth": 10, "field_count": 4, "operation_type": "query",
        "field_paths": ["a", "a.b", "a.b.c", "a.b.c.d"],
        "params": {"depth_limit": 10}
    }
}

test_depth_over_limit_blocked if {
    some msg in deny with input as {
        "depth": 11, "field_count": 5, "operation_type": "query",
        "field_paths": ["a", "a.b", "a.b.c", "a.b.c.d", "a.b.c.d.e"],
        "params": {"depth_limit": 10}
    }
    startswith(msg, "query depth 11 exceeds limit")
}

test_depth_limit_from_params if {
    # When params provides depth_limit=10 but real depth is 15, blocked
    deny["query depth 15 exceeds limit 10"] with input as {
        "depth": 15, "field_count": 3, "operation_type": "query",
        "field_paths": ["a", "a.b"],
        "params": {"depth_limit": 10}
    }
}
