# Sample 20: source-ip-filtering.rego
# Topic: CIDR-based access control
#
# NOTE: This policy requires the Go sidecar to populate input.source_ip.
# This works automatically in standalone proxy mode (r.RemoteAddr is the
# client's real IP). In sidecar/K8s mode, r.RemoteAddr is the pod IP of
# the previous hop — configure --trusted-proxy-cidr to enable
# X-Forwarded-For parsing, or populate input.source_ip via your own
# middleware.
#
# BUILT-IN: net.cidr_contains(cidr, ip) — OPA's built-in function for
# IP address matching. Supports IPv4 and IPv6 CIDR notation.
#
# USE CASES:
#   - Block internal admin endpoints from external IPs
#   - Allow mutations only from VPN CIDR ranges
#   - Block known attack IP ranges during incidents
#
# PARAM: input.params.blocked_cidrs (array of CIDR strings)
# PARAM: input.params.allowed_cidrs (array of CIDR strings)

package graphql

default allow := false

allow if {
    count(deny) == 0
}

# Block requests from known-bad IP ranges
deny contains msg if {
    input.source_ip
    some cidr in input.params.blocked_cidrs
    net.cidr_contains(cidr, input.source_ip)
    msg := sprintf("requests from %q are blocked (CIDR: %v)", [input.source_ip, cidr])
}

# Only allow requests from specific IP ranges
deny contains msg if {
    input.source_ip
    count(input.params.allowed_cidrs) > 0
    not ip_in_allowed_cidrs
    msg := sprintf("requests from %q are not from an allowed network", [input.source_ip])
}

ip_in_allowed_cidrs if {
    some cidr in input.params.allowed_cidrs
    net.cidr_contains(cidr, input.source_ip)
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_ip_not_in_blocklist_allowed if {
    allow with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["hello"], "source_ip": "1.2.3.4",
        "params": {"blocked_cidrs": ["10.0.0.0/8"]}
    }
}

test_ip_in_blocklist_denied if {
    some msg in deny with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["hello"], "source_ip": "10.0.0.5",
        "params": {"blocked_cidrs": ["10.0.0.0/8"]}
    }
    startswith(msg, "requests from \"10.0.0.5\" are blocked")
}

test_ip_not_in_allowlist if {
    some msg in deny with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["hello"], "source_ip": "1.2.3.4",
        "params": {"allowed_cidrs": ["192.168.0.0/16"]}
    }
    startswith(msg, "requests from \"1.2.3.4\" are not from an allowed network")
}
