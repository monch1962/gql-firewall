# Sample 01: deny-override-structure.rego
# Topic: The deny-override pattern explained
#
# This is the simplest possible gql-firewall policy. Every custom policy
# starts with this skeleton. Learn it once, use it everywhere.
#
# HOW IT WORKS:
# - default allow := false  →  every request is BLOCKED unless a rule
#   explicitly allows it. This is the safe default.
# - allow if { count(deny) == 0 }  →  the ONLY allow rule. It checks
#   whether any deny rule produced a result. If the deny set is empty,
#   the request passes.
# - deny contains <string> if { <condition> }  →  each deny rule adds
#   a reason string to the deny set. The firewall returns the first
#   reason as the 403 "reason" field.
#
# WHY count(deny) == 0 instead of "not deny"?
# In Rego v1, "deny" is a SET. "not deny" checks whether the expression
# produces bindings — but a set always produces a value (even empty).
# So "not deny" would always be false. "count(deny) == 0" correctly
# checks if the set has zero elements.
#
# See: tutorial.md → "Policy anatomy — deny-override model"
package graphql

default allow := false

allow if {
    count(deny) == 0
}

# ── Example deny rule ───────────────────────────────────────────────────────
# This rule always blocks. Replace the condition with your own logic.
deny contains "example: every request is blocked by this rule" if {
    true
}

# ── Tests ───────────────────────────────────────────────────────────────────
test_baseline_denied if {
    # With no deny rules firing, verify the structure works
    some msg in deny with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["hello"], "params": {}
    }
    startswith(msg, "example:")
}
