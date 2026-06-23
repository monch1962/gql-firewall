# Sample 10: field-blocklist.rego
# Topic: Block sensitive fields (PII)
# OWASP: API3 — Excessive Data Exposure
#
# ATTACK: A client requests fields it shouldn't have access to:
#   { user { ssn password creditCard internalNotes } }
# GraphQL's field-selection model means the server returns whatever the
# client asks for — there's no built-in field-level access control.
#
# DEFENCE: Maintain a blocklist of sensitive dot-separated field paths.
# The firewall checks each requested path against the blocklist and blocks
# the entire request if any match is found.
#
# PATH MATCHING IS EXACT: "user.ssn" matches only "user.ssn", not "ssn"
# or "admin.ssn". If you need prefix or suffix matching, use startswith
# or endswith like sample 07 (introspection blocking).
#
# PARAM: input.params.field_blocklist (array of strings)
#
# See also: sample 11 (field-allowlist.rego) for the inverse approach

package graphql

default allow := false

allow if {
    count(deny) == 0
}

deny contains msg if {
    some blocked in input.params.field_blocklist
    some path in input.field_paths
    path == blocked
    msg := sprintf("field %q is blocked", [path])
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_safe_fields_allowed if {
    allow with input as {
        "depth": 2, "field_count": 3, "operation_type": "query",
        "field_paths": ["user", "user.name", "user.email"],
        "params": {"depth_limit": 10, "field_blocklist": ["user.ssn", "user.password"]}
    }
}

test_blocked_field_rejected if {
    some msg in deny with input as {
        "depth": 2, "field_count": 3, "operation_type": "query",
        "field_paths": ["user", "user.ssn"],
        "params": {"field_blocklist": ["user.ssn"]}
    }
    msg == `field "user.ssn" is blocked`
}

test_exact_path_matching if {
    # "ssn" alone is NOT in the blocklist (only "user.ssn" is)
    allow with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["ssn"],
        "params": {"field_blocklist": ["user.ssn"]}
    }
}

test_empty_blocklist_blocks_nothing if {
    allow with input as {
        "depth": 2, "field_count": 2, "operation_type": "query",
        "field_paths": ["user", "user.ssn"],
        "params": {"field_blocklist": []}
    }
}
