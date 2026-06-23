# Sample 15: fragment-spread-limiter.rego
# Topic: Fragment explosion protection
#
# ATTACK: GraphQL fragments can spread across many types or interfaces,
# multiplying query cost:
#   query {
#     ... on User { name }
#     ... on Admin { name }
#     ... on Moderator { name }
#     ... on SuperAdmin { name }
#     # 50+ more type spreads
#   }
# Each ... on Type forces the server to check the runtime type and resolve
# the corresponding fields. 100+ spreads can cause quadratic resolution cost.
#
# DEFENCE: Count the total number of fragment spreads (both named fragments
# like ...MyFragment and inline fragments like ... on Type) and block when
# the count exceeds a threshold.
#
# TYPICAL THRESHOLDS:
#   - 0-5: No fragments or minimal use
#   - 5-15: Moderate fragment usage (typical for production)
#   - 30+: Suspicious — likely an attack or poorly-structured query
#
# PARAM: input.params.max_fragment_spreads (number, default 15)

package graphql

default allow := false

allow if {
    count(deny) == 0
}

deny contains msg if {
    input.params.max_fragment_spreads
    input.fragment_spread_count > input.params.max_fragment_spreads
    msg := sprintf("fragment spread count %d exceeds limit %v", [input.fragment_spread_count, input.params.max_fragment_spreads])
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_moderate_fragment_use_allowed if {
    allow with input as {
        "depth": 3, "field_count": 5, "operation_type": "query",
        "field_paths": ["user", "user.name", "user.email"],
        "fragment_spread_count": 3,
        "params": {"max_fragment_spreads": 15}
    }
}

test_fragment_explosion_blocked if {
    some msg in deny with input as {
        "depth": 3, "field_count": 60, "operation_type": "query",
        "field_paths": ["user", "user.name"],
        "fragment_spread_count": 50,
        "params": {"max_fragment_spreads": 15}
    }
    startswith(msg, "fragment spread count 50 exceeds limit")
}
