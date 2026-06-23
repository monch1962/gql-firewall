# Sample 13: argument-depth-limiter.rego
# Topic: Max argument nesting
#
# ATTACK: Arguments in GraphQL can contain nested objects:
#   users(filter: { age: { gt: 18 }, city: { name: { eq: "NYC" } } })
# Deeply nested argument objects can:
#   - Exploit poorly-written resolvers that recursively process inputs
#   - Trigger expensive validation chains
#   - Bypass shallow-query limits (depth is about fields, not args)
#
# DEFENCE: Measure the nesting depth of argument values and block when
# it exceeds a threshold. A shallow query with deep arguments is the
# attack signature.
#
# NORMAL vs ATTACK:
#   Normal: user(id: 42)                   → depth 1
#   Normal: posts(filter: { published: true }) → depth 2
#   Attack: users(filter: { a: { b: { c: { d: { e: 1 } } } } }) → depth 5+
#
# PARAM: input.params.max_argument_depth (number, default 5)

package graphql

default allow := false

allow if {
    count(deny) == 0
}

deny contains msg if {
    input.params.max_argument_depth
    input.argument_depth > input.params.max_argument_depth
    msg := sprintf("argument depth %d exceeds limit %v", [input.argument_depth, input.params.max_argument_depth])
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_flat_argument_allowed if {
    allow with input as {
        "depth": 2, "field_count": 2, "operation_type": "query",
        "field_paths": ["user", "user.name"], "argument_depth": 1,
        "params": {"max_argument_depth": 5}
    }
}

test_nested_argument_blocked if {
    some msg in deny with input as {
        "depth": 2, "field_count": 2, "operation_type": "query",
        "field_paths": ["user", "user.name"], "argument_depth": 10,
        "params": {"max_argument_depth": 5}
    }
    startswith(msg, "argument depth 10 exceeds limit")
}
