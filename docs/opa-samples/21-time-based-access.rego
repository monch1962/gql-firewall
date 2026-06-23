# Sample 21: time-based-access.rego
# Topic: Time-of-day restrictions
#
# USE CASES:
#   — Block expensive mutations during peak hours (9am-5pm)
#   — Allow writes only during maintenance windows
#   — Rate-limit differently at night vs day
#
# HOW IT WORKS: The firewall calls the Rego policy at evaluation time.
# OPA's time built-in functions (time.now_ns, time.clock) return the
# current wall-clock time. Your policy uses these to make time-based
# decisions.
#
# PATTERN: time.clock([time.now_ns(), "UTC"]) returns [hour, minute, second].
# Compare the hour against your allowed window.
#
# CAVEATS:
#   - Time is evaluated on the FIREWALL host, not the client host.
#     If your firewall runs in a different timezone, synchronise with
#     the timezone parameter.
#   - OPA caches results. If you use time-based rules, ensure the cache
#     TTL (--opa-cache-ttl) is short enough that time-of-day changes
#     take effect promptly.
#   - Testing time-based rules requires overriding the time with the
#     "with time" construct, which is non-trivial. Test the rule logic
#     separately from the time dependency.
#
# PARAM: input.params.peak_hour_start (number, default 9)
# PARAM: input.params.peak_hour_end (number, default 17)

package graphql

default allow := false

allow if {
    count(deny) == 0
}

deny contains msg if {
    input.params.block_mutations_during_peak == true
    input.operation_type == "mutation"
    input.params.peak_hour_start
    input.params.peak_hour_end
    current_hour := time.clock([time.now_ns(), "UTC"])[0]
    current_hour >= input.params.peak_hour_start
    current_hour < input.params.peak_hour_end
    msg := sprintf("mutations blocked during peak hours (%v:00-%v:00 UTC)", [
        input.params.peak_hour_start, input.params.peak_hour_end])
}

# ── Tests ───────────────────────────────────────────────────────────────────

# Note: Time-based rules are tested with static input assertions.
# The rule below uses params to control whether the rule fires.
# Actual time-of-day testing requires integration tests against the
# Go sidecar.

test_mutation_allowed_outside_peak if {
    # Without block_mutations_during_peak, the rule doesn't fire
    allow with input as {
        "depth": 1, "field_count": 1, "operation_type": "mutation",
        "field_paths": ["createUser"],
        "params": {"block_mutations_during_peak": false}
    }
}
