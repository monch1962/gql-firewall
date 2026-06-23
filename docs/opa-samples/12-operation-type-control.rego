# Sample 12: operation-type-control.rego
# Topic: Block or allow specific operation types
#
# USE CASES:
# - Block subscriptions in production (expensive WebSocket connections)
# - Block mutations in read replicas (avoid write amplification)
# - Allow only queries in public APIs (ratelimit mutations separately)
# - Block specific operation types per tenant
#
# TWO MECHANISMS (can be used together or separately):
# 1. blocked_operations: list of operation types to block
# 2. allowed_operations: ONLY these types are permitted
#
# When BOTH are set, ALLOWED takes precedence (wins over BLOCKED).
# This lets you say "only queries allowed" but still explicitly
# call out subscriptions as blocked for logging purposes.
#
# PARAM: input.params.blocked_operations (array of strings)
# PARAM: input.params.allowed_operations (array of strings)

package graphql

default allow := false

allow if {
    count(deny) == 0
}

deny contains msg if {
    some blocked in input.params.blocked_operations
    input.operation_type == blocked
    msg := sprintf("operation type %q is blocked", [input.operation_type])
}

deny contains msg if {
    count(input.params.allowed_operations) > 0
    count({op | op = input.params.allowed_operations[_]; op == input.operation_type}) == 0
    msg := sprintf("operation type %q is not allowed", [input.operation_type])
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_query_not_in_blocked_list if {
    allow with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["hello"],
        "params": {"blocked_operations": ["subscription"]}
    }
}

test_subscription_blocked if {
    some msg in deny with input as {
        "depth": 1, "field_count": 1, "operation_type": "subscription",
        "field_paths": ["hello"],
        "params": {"blocked_operations": ["subscription"]}
    }
    msg == "operation type \"subscription\" is blocked"
}

test_allowed_operations_only if {
    some msg in deny with input as {
        "depth": 1, "field_count": 1, "operation_type": "mutation",
        "field_paths": ["hello"],
        "params": {"allowed_operations": ["query"]}
    }
    msg == "operation type \"mutation\" is not allowed"
}
