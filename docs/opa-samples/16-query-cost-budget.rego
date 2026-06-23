# Sample 16: query-cost-budget.rego
# Topic: Complexity budget (depth × field_count)
# OWASP: API4 — Mass Assignment
#
# RATIONALE: Depth-only and field-count-only limits are fragile — an
# attacker can stay under both while still causing measurable load.
# For example:
#   depth=3, fields=50 → passes depth limit, fails field limit
#   depth=20, fields=1 → fails depth limit, passes field limit
#
# A COMBINED METRIC catches both: depth × field_count
# This approximates the "query complexity" as the product of width and
# depth — the total number of resolver invocations.
#
# EXAMPLES:
#   depth=3, fields=10 → cost=30  (safe)
#   depth=5, fields=50 → cost=250 (expensive)
#   depth=20, fields=50 → cost=1000 (attack)
#
# NOTE: This is a heuristic. Real query cost depends on resolver cost,
# not just field count. For production, calibrate cost_budget against
# your actual resolver latency.
#
# PARAM: input.params.cost_budget (number, default 50)

package graphql

default allow := false

allow if {
    count(deny) == 0
}

deny contains msg if {
    input.params.cost_budget
    (input.depth * input.field_count) > input.params.cost_budget
    msg := sprintf("query cost %d exceeds budget %v", [input.depth * input.field_count, input.params.cost_budget])
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_low_cost_allowed if {
    allow with input as {
        "depth": 3, "field_count": 3, "operation_type": "query",
        "field_paths": ["a", "a.b", "a.b.c"],
        "params": {"cost_budget": 50}
    }
}

test_high_cost_blocked if {
    some msg in deny with input as {
        "depth": 20, "field_count": 10, "operation_type": "query",
        "field_paths": ["hello"],
        "params": {"cost_budget": 50}
    }
    startswith(msg, "query cost 200 exceeds budget 50")
}

test_cost_budget_not_set if {
    allow with input as {
        "depth": 50, "field_count": 100, "operation_type": "query",
        "field_paths": ["hello"],
        "params": {}
    }
}
