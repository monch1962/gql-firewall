# Sample 04: testing-patterns.rego
# Topic: How to write and run tests
#
# OPA has a built-in test framework using "with input as" to provide
# test data. Tests are Rego rules that start with "test_".
#
# THREE TEST PATTERNS:
#
# 1. Positive: assert that a deny rule fires
#   test_foo_blocked if {
#       some msg in deny with input as { ... }
#       msg == "expected reason"
#   }
#
# 2. Negative: assert that allow is true (no deny fires)
#   test_foo_allowed if {
#       allow with input as { ... }
#   }
#
# 3. Message substring: assert deny reason contains text
#   test_foo_blocked if {
#       some msg in deny with input as { ... }
#       startswith(msg, "partial reason")
#   }
#
# RUNNING TESTS:
#   opa test docs/opa-samples/04-testing-patterns.rego -v
#   opa test docs/opa-samples/ --coverage
#
# TEST STRUCTURE:
#   test_<descriptive_name> if { <assertion> }
#
# Each test is a RULE. If the rule body evaluates to true, the test
# passes. If it produces an undefined result or false, the test fails.
#
# See: tutorial.md → "Testing policies with opa test"

package graphql

default allow := false

allow if {
    count(deny) == 0
}

# ── A simple deny rule (for demonstration) ──────────────────────────────────

deny contains msg if {
    input.operation_type == "subscription"
    msg := "subscriptions are blocked"
}

deny contains msg if {
    input.depth > input.params.depth_limit
    msg := sprintf("depth exceeded %v", [input.params.depth_limit])
}

# ── Tests ───────────────────────────────────────────────────────────────────

# Pattern 1: Exact match on deny reason
test_subscription_blocked if {
    some msg in deny with input as {
        "depth": 1, "field_count": 1, "operation_type": "subscription",
        "field_paths": ["hello"],
        "params": {"depth_limit": 10}
    }
    msg == "subscriptions are blocked"
}

# Pattern 2: Allow when no rules fire
test_query_allowed if {
    allow with input as {
        "depth": 5, "field_count": 3, "operation_type": "query",
        "field_paths": ["hello"],
        "params": {"depth_limit": 10}
    }
}

# Pattern 3: Substring match on deny reason
test_depth_blocked if {
    some msg in deny with input as {
        "depth": 15, "field_count": 3, "operation_type": "query",
        "field_paths": ["hello"],
        "params": {"depth_limit": 10}
    }
    startswith(msg, "depth exceeded")
}

# Combining: assert multiple conditions in one test
test_multiple_deny_conditions_not_fired if {
    # This test verifies that a query with no issues is allowed
    allow with input as {
        "depth": 3, "field_count": 2, "operation_type": "query",
        "field_paths": ["hello"],
        "params": {"depth_limit": 10}
    }
}
