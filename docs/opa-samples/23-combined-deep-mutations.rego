# Sample 23: combined-deep-mutations.rego
# Topic: Intersection rule — mutation + depth
#
# RATIONALE: Queries can legitimately be deep (nested relations, recursive
# types). But MUTATIONS that are deep are suspicious — most mutations
# update a single entity and shouldn't need more than 2-3 levels of nesting.
#
# This is an INTERSECTION rule: it only fires when BOTH conditions are
# true (operation is a mutation AND depth exceeds limit). Queries at
# any depth pass freely; mutations beyond 3 levels are blocked.
#
# This pattern generalises to any multi-condition rule:
#   - Block expensive reads from slow tenants
#   - Block fragment-heavy subscriptions
#   - Block batched queries from unauthenticated callers
#   - Block deep queries containing specific fields
#
# PARAM: input.params.mutation_depth_limit (number, default 3)
# PARAM: input.params.blocked_mutations (array of strings)

package graphql

default allow := false

allow if {
    count(deny) == 0
}

# Deep mutations are blocked (mutation + depth)
deny contains msg if {
    input.operation_type == "mutation"
    input.params.mutation_depth_limit
    input.depth > input.params.mutation_depth_limit
    msg := sprintf("mutation depth %d exceeds limit %v", [input.depth, input.params.mutation_depth_limit])
}

# Specific mutation names are blocked (by name)
deny contains msg if {
    input.operation_type == "mutation"
    some blocked in input.params.blocked_mutations
    input.operation_name == blocked
    msg := sprintf("mutation %q is blocked", [input.operation_name])
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_deep_query_not_blocked if {
    # Query at depth 10 passes — mutation limit is 3, but this is a QUERY
    allow with input as {
        "depth": 10, "field_count": 5, "operation_type": "query",
        "field_paths": ["a", "a.b", "a.b.c", "a.b.c.d"],
        "params": {"mutation_depth_limit": 3}
    }
}

test_deep_mutation_blocked if {
    some msg in deny with input as {
        "depth": 5, "field_count": 5, "operation_type": "mutation",
        "field_paths": ["updateUser"],
        "params": {"mutation_depth_limit": 3}
    }
    startswith(msg, "mutation depth 5 exceeds limit 3")
}

test_named_mutation_blocked if {
    some msg in deny with input as {
        "depth": 1, "field_count": 1, "operation_type": "mutation",
        "field_paths": ["bulkImport"], "operation_name": "bulkImport",
        "params": {"blocked_mutations": ["bulkImport", "adminDelete"]}
    }
    msg == "mutation \"bulkImport\" is blocked"
}
