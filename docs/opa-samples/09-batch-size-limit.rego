# Sample 09: batch-size-limit.rego
# Topic: Block multi-operation requests
#
# ATTACK: GraphQL allows sending multiple operations in one request:
#   query Q1 { expensiveField } query Q2 { expensiveField }
# This bypasses per-request rate limits — 1 HTTP request = N operations.
# An attacker can send 50 operations in a single POST to amplify cost.
#
# DEFENCE: Count operations in the request (input.batch_size) and block
# when the count exceeds a threshold.
#
# NOTE: Some clients legitimately batch queries (e.g., Apollo's
# automatic persisted queries sends each PQ as a separate operation
# in the same request). Set max_batch_size to 5-10 if you use APQ.
#
# PARAM: input.params.max_batch_size (number, default 1)

package graphql

default allow := false

allow if {
    count(deny) == 0
}

deny contains msg if {
    input.params.max_batch_size
    input.batch_size > input.params.max_batch_size
    msg := sprintf("batch size %d exceeds limit %v", [input.batch_size, input.params.max_batch_size])
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_single_operation_allowed if {
    allow with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["hello"], "batch_size": 1,
        "params": {"max_batch_size": 1}
    }
}

test_multi_operation_blocked if {
    some msg in deny with input as {
        "depth": 1, "field_count": 2, "operation_type": "query",
        "field_paths": ["a", "b"], "batch_size": 5,
        "params": {"max_batch_size": 1}
    }
    startswith(msg, "batch size 5 exceeds limit")
}

test_no_param_no_enforcement if {
    allow with input as {
        "depth": 1, "field_count": 2, "operation_type": "query",
        "field_paths": ["a", "b"], "batch_size": 50,
        "params": {}
    }
}
