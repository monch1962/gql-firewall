# Sample 08: directive-limit.rego
# Topic: Limit @directive usage
#
# ATTACK: Custom directives like @transform, @fetch, @delay, or @waterfall
# can trigger expensive server-side operations. An attacker who spikes the
# directive count can exhaust CPU even with low depth/field counts.
#
# Example dangerous directives:
#   @delay(ms: 5000) — forces the server to wait 5 seconds per field
#   @fetch(url: "...") — triggers a server-side HTTP request
#   @transform — runs an arbitrary transformation pipeline
#
# DEFENCE: Count total @directive usages across all fields and block when
# the count exceeds a threshold. The threshold depends on your schema:
#   - 0-2: very strict (no caching, no fetch directives)
#   - 3-5: moderate (allows typical @skip/@include patterns)
#   - 10+: permissive (allows heavy directive use)
#
# PARAM: input.params.max_directives (number, default 5)

package graphql

default allow := false

allow if {
    count(deny) == 0
}

deny contains msg if {
    input.params.max_directives
    input.directives > input.params.max_directives
    msg := sprintf("directive count %d exceeds limit %v", [input.directives, input.params.max_directives])
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_reasonable_directive_count_allowed if {
    allow with input as {
        "depth": 2, "field_count": 3, "operation_type": "query",
        "field_paths": ["users", "users.name"], "directives": 3,
        "params": {"max_directives": 5}
    }
}

test_excessive_directives_blocked if {
    some msg in deny with input as {
        "depth": 2, "field_count": 5, "operation_type": "query",
        "field_paths": ["users", "users.name"], "directives": 50,
        "params": {"max_directives": 5}
    }
    msg == "directive count 50 exceeds limit 5"
}

test_no_param_no_enforcement if {
    # When max_directives is not in params, the guard
    # "input.params.max_directives" evaluates to false,
    # so the rule doesn't fire.
    allow with input as {
        "depth": 2, "field_count": 3, "operation_type": "query",
        "field_paths": ["hello"], "directives": 999,
        "params": {}
    }
}
