# Sample 11: field-allowlist.rego
# Topic: Only allow specific fields
# OWASP: API3 — Excessive Data Exposure
#
# APPROACH (inverse of blocklist): Instead of naming fields to block,
# name the ONLY fields that are allowed. Any field NOT in the allowlist
# is blocked.
#
# When to use blocklist vs allowlist:
#   BLOCKLIST: Your schema has 200 fields, 5 are sensitive.
#              Use blocklist — maintainability wins.
#   ALLOWLIST: Your schema has 200 fields, only 10 should be
#              publicly accessible. Use allowlist — safety wins.
#
# ANCESTOR MATCHING: "user" in the allowlist permits all of:
#   user, user.name, user.ssn, user.posts.title
# This is because field_on_allowlist checks both exact match AND
# prefix match (startswith). Without ancestor matching, you'd need to
# list every single leaf field.
#
# PARAM: input.params.field_allowlist (array of strings)

package graphql

default allow := false

allow if {
    count(deny) == 0
}

deny contains msg if {
    count(input.params.field_allowlist) > 0
    some path in input.field_paths
    not field_on_allowlist(path)
    msg := sprintf("field %q is not in the allowlist", [path])
}

field_on_allowlist(path) if {
    some permitted in input.params.field_allowlist
    path == permitted
}

field_on_allowlist(path) if {
    some permitted in input.params.field_allowlist
    startswith(path, permitted)
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_allowed_field_passes if {
    allow with input as {
        "depth": 2, "field_count": 2, "operation_type": "query",
        "field_paths": ["user", "user.name"],
        "params": {"field_allowlist": ["user", "user.name", "user.email"]}
    }
}

test_ancestor_in_allowlist_covers_nested if {
    # "user" is in the allowlist → "user.name" and "user.ssn" are both allowed
    allow with input as {
        "depth": 2, "field_count": 2, "operation_type": "query",
        "field_paths": ["user", "user.ssn"],
        "params": {"field_allowlist": ["user"]}
    }
}

test_unknown_field_blocked if {
    some msg in deny with input as {
        "depth": 2, "field_count": 2, "operation_type": "query",
        "field_paths": ["user", "user.ssn"],
        "params": {"field_allowlist": ["user.name", "user.email"]}
    }
    msg == "field \"user.ssn\" is not in the allowlist"
}

test_allowlist_not_set_means_no_restriction if {
    allow with input as {
        "depth": 2, "field_count": 2, "operation_type": "query",
        "field_paths": ["user", "user.ssn"],
        "params": {}
    }
}
