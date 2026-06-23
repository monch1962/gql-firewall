# Sample 03: parameterisation.rego
# Topic: Params vs hardcoded values
#
# The firewall populates input.params from your JSON config file or admin
# API. Parametrising your policy means you can change limits at runtime
# without editing Rego files or restarting the firewall.
#
# PARAMETER SOURCES (in priority order):
# 1. Admin API:  POST /admin/rules/update  {"depth_limit": 5}
# 2. JSON file:  --opa-params config/params.json
# 3. Code default: hardcoded in the Rego file (fallback)
#
# PATTERN: default + parameter override
#   default my_param := 10       ← code default (always present)
#   my_param := input.params.my_param if input.params.my_param  ← override
#
# This ensures the policy works even if params are missing (graceful
# degradation — the default applies).
#
# PATTERN: guard access
#   input.params.my_param        ← checks existence first
#   input.depth > input.params.my_param  ← then accesses the value
#
# If you skip the guard and input.params is null, the rule evaluation
# halts and the request might be blocked incorrectly.
#
# See: tutorial.md → "Parameterisation"

package graphql

default allow := false

allow if {
    count(deny) == 0
}

# ── Parameter with default ──────────────────────────────────────────────────
default param_depth_limit := 10
param_depth_limit := input.params.depth_limit if input.params.depth_limit

default param_allow_anonymous := false
param_allow_anonymous := input.params.allow_anonymous if input.params.allow_anonymous

deny contains msg if {
    input.depth > param_depth_limit
    msg := sprintf("depth %d exceeds limit %d", [input.depth, param_depth_limit])
}

deny contains "anonymous queries blocked" if {
    not param_allow_anonymous
    input.operation_name == ""
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_depth_with_param_overrides if {
    # depth_limit=5 from params overrides default 10
    deny["depth 7 exceeds limit 5"] with input as {
        "depth": 7, "field_count": 3, "operation_type": "query",
        "field_paths": ["a", "a.b"],
        "params": {"depth_limit": 5}
    }
}

test_depth_with_default if {
    # No depth_limit in params → default 10 applies
    deny["depth 12 exceeds limit 10"] with input as {
        "depth": 12, "field_count": 3, "operation_type": "query",
        "field_paths": ["a", "a.b"],
        "params": {}
    }
}
