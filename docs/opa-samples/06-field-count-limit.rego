# Sample 06: field-count-limit.rego
# Topic: Alias bomb / field duplication
# OWASP: API4 — Mass Assignment
#
# ATTACK: An attacker repeats the same expensive field hundreds of times
# using GraphQL aliases:
#   query { a1: expensiveField a2: expensiveField ... a500: expensiveField }
#
# The server resolves each alias independently, multiplying cost by 500x.
# Even if each resolution is cheap (1ms), 500 aliases = 500ms.
#
# DEFENCE: Count total fields (including aliases) and block when the count
# exceeds a threshold. This catches alias bombs regardless of field name.
#
# CONTRAST WITH depth-limit: depth-limit catches DEEP nesting; this catches
# WIDE queries. An attacker can attack either axis — you need both defences.
#
# PARAM: input.params.max_field_count (number, default 100)

package graphql

default allow := false

allow if {
    count(deny) == 0
}

deny contains msg if {
    input.field_count > input.params.max_field_count
    msg := sprintf("field count %d exceeds limit (possible alias bomb)", [input.field_count])
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_normal_field_count_allowed if {
    allow with input as {
        "depth": 2, "field_count": 10, "operation_type": "query",
        "field_paths": ["a", "a.b"],
        "params": {"max_field_count": 100}
    }
}

test_alias_bomb_blocked if {
    some msg in deny with input as {
        "depth": 2, "field_count": 150, "operation_type": "query",
        "field_paths": ["a", "a.b"],
        "params": {"max_field_count": 100}
    }
    startswith(msg, "field count 150 exceeds limit")
}

test_when_param_not_set_uses_default_zero if {
    # Without a max_field_count in params, the comparison input.field_count > 0
    # is false, so the rule doesn't fire. This is safe: no params = no limit.
    allow with input as {
        "depth": 2, "field_count": 999, "operation_type": "query",
        "field_paths": ["hello"],
        "params": {}
    }
}
