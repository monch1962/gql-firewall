# Sample 17: persisted-query-enforcement.rego
# Topic: Block dynamic queries
#
# WHAT: In persisted query (PQ) mode, only queries with a known hash
# are allowed. The client sends the hash instead of the full query text,
# and the server looks up the query from a registry.
#
# WHY: Persisted queries prevent:
#   - Arbitrary query injection (the client can only run registered queries)
#   - Schema exploration (attacker can't discover types by trial and error)
#   - Query size attacks (the hash is always 16 chars, not 100KB)
#
# HOW THE FIREWALL DETECTS PQS:
#   A query hash is generated from the first 8 bytes of SHA-256 of the
#   query string. When the client sends a named, non-hashed operation,
#   input.query_hash is empty. This rule blocks those.
#
# Two reasons a query might not have a hash:
#   1. It's a dynamic query (no operation name at all)
#   2. It has a name but no hash (named but not registered)
#
# Reason 2 is suspicious — named operations sent without a hash suggest
# a client that's probing the API with known operation names but without
# going through the PQ protocol.
#
# PARAM: input.params.require_persisted_queries (boolean, default false)

package graphql

default allow := false

allow if {
    count(deny) == 0
}

deny contains "dynamic queries are not allowed" if {
    input.params.require_persisted_queries == true
    not input.operation_name
    not input.query_hash
}

deny contains msg if {
    input.params.require_persisted_queries == true
    input.operation_name
    not input.query_hash
    msg := sprintf("persisted query %q has no matching hash", [input.operation_name])
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_dynamic_query_blocked_when_required if {
    deny["dynamic queries are not allowed"] with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["hello"], "operation_name": "",
        "params": {"require_persisted_queries": true}
    }
}

test_named_but_not_hashed if {
    some msg in deny with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["hello"], "operation_name": "GetUser",
        "query_hash": "",
        "params": {"require_persisted_queries": true}
    }
    msg == "persisted query \"GetUser\" has no matching hash"
}

test_named_and_hashed_is_allowed if {
    allow with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["hello"], "operation_name": "GetUser",
        "query_hash": "a1b2c3d4",
        "params": {"require_persisted_queries": true}
    }
}

test_pq_not_required_query_passes if {
    allow with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["hello"], "operation_name": "",
        "params": {"require_persisted_queries": false}
    }
}
