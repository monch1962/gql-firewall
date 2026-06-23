# Sample 22: deprecate-query-hash.rego
# Topic: Block deprecated query versions
#
# WHAT: Persisted queries have known SHA-256 hashes. When you deprecate
# a query version in your client library, add its hash to the blocklist.
# Clients that haven't updated receive a clear error message directing
# them to the new version.
#
# USE CASES:
#   - Sunset an old API version (v1 → v2 migration)
#   - Block a query with a known vulnerability
#   - Force clients to use a newer, more efficient query pattern
#   - Phase out deprecated fields without breaking the whole schema
#
# WORKFLOW:
#   1. Client A sends hash "d4e5f6a1" (deprecated query)
#   2. Firewall blocks with reason "this query version is deprecated"
#   3. Client A's error handler logs the message
#   4. Client A fetches the new query from your CDN
#   5. Client A sends hash "b7c8d9e2" (current query) — passes
#
# PARAM: input.params.deprecated_query_hashes (array of hex strings)

package graphql

default allow := false

allow if {
    count(deny) == 0
}

deny contains msg if {
    some hash in input.params.deprecated_query_hashes
    input.query_hash == hash
    msg := sprintf("query hash %q is deprecated — update your client", [input.query_hash])
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_current_hash_allowed if {
    allow with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["hello"], "query_hash": "b7c8d9e2",
        "params": {"deprecated_query_hashes": ["a1b2c3d4", "e5f6a7b8"]}
    }
}

test_deprecated_hash_blocked if {
    some msg in deny with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["hello"], "query_hash": "a1b2c3d4",
        "params": {"deprecated_query_hashes": ["a1b2c3d4", "e5f6a7b8"]}
    }
    msg == "query hash \"a1b2c3d4\" is deprecated — update your client"
}
