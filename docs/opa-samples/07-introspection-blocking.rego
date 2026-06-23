# Sample 07: introspection-blocking.rego
# Topic: Block __schema, __type, __typename
# OWASP: API8 — Injection
#
# ATTACK: GraphQL introspection lets clients discover the entire schema —
# all types, fields, arguments, directives, and deprecation notices.
# While useful for development, exposing introspection in production lets
# attackers map your entire API surface:
#   - Find undocumented fields (admin endpoints, internal mutations)
#   - Discover argument types for injection attacks
#   - Find deprecated fields that may have security gaps
#   - Map relationships between types (users → posts → admin)
#
# DEFENCE: Block requests containing __schema, __type, or __typename,
# both as top-level fields (__schema) and nested fields (user.__typename).
# Also block named IntrospectionQuery operations.
#
# THREE MATCH PATTERNS:
# 1. Exact field match:   __schema == input.field_paths[_]
# 2. Suffix match:        user.__typename (endswith with dot prefix)
# 3. Operation name:      operation_name == "IntrospectionQuery"

package graphql

default allow := false

allow if {
    count(deny) == 0
}

# Named introspection query
deny contains "introspection queries are blocked" if {
    input.operation_name == "IntrospectionQuery"
}

# Direct introspection fields
introspection_fields := {"__schema", "__type", "__typename"}

deny contains msg if {
    some f in introspection_fields
    f == input.field_paths[_]
    msg := sprintf("introspection field %q is blocked", [f])
}

# Nested introspection (e.g., user.__typename)
deny contains msg if {
    some f in introspection_fields
    some path in input.field_paths
    endswith(path, concat("", [".", f]))
    msg := sprintf("nested introspection field %q is blocked", [f])
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_block_named_introspection if {
    deny["introspection queries are blocked"] with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["__schema"], "operation_name": "IntrospectionQuery",
        "params": {}
    }
}

test_block_top_level_schema if {
    some msg in deny with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["__schema"],
        "params": {}
    }
    startswith(msg, "introspection field")
}

test_block_nested_typename if {
    some msg in deny with input as {
        "depth": 2, "field_count": 2, "operation_type": "query",
        "field_paths": ["user", "user.__typename"],
        "params": {}
    }
    startswith(msg, "nested introspection field")
}

test_normal_field_allowed if {
    allow with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["user.name"], "operation_name": "GetUser",
        "params": {"depth_limit": 10}
    }
}
