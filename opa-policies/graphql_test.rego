# OPA Rego policy tests for the GraphQL firewall (deny-override model).
# Run: opa test opa-policies/
package graphql

# Depth: under limit should be allowed
test_depth_allow if {
	allow with input as {"depth": 5, "field_count": 3, "operation_type": "query", "field_paths": ["user", "user.name"]}
}

# Depth: over limit should be denied
test_depth_block if {
	deny["query exceeds depth limit"] with input as {"depth": 20, "field_count": 3, "operation_type": "query", "field_paths": ["user", "user.name"]}
}

# Field allow: safe field
test_field_allow if {
	allow with input as {"depth": 1, "field_count": 1, "operation_type": "query", "field_paths": ["user.name"]}
}

# Field block: SSN field should be denied
test_field_block_ssn if {
	deny["blocked field requested"] with input as {"depth": 2, "field_count": 2, "operation_type": "query", "field_paths": ["user", "user.ssn"]}
}

# Field block: __schema should be denied
test_field_block_schema if {
	deny["blocked field requested"] with input as {"depth": 1, "field_count": 1, "operation_type": "query", "field_paths": ["__schema"]}
}

# Operation: query allowed
test_query_allowed if {
	allow with input as {"depth": 1, "field_count": 1, "operation_type": "query", "field_paths": ["hello"]}
}

# Operation: mutation allowed
test_mutation_allowed if {
	allow with input as {"depth": 1, "field_count": 1, "operation_type": "mutation", "field_paths": ["create"]}
}

# Operation: subscription denied
test_subscription_blocked if {
	deny["subscriptions are not allowed"] with input as {"depth": 1, "field_count": 1, "operation_type": "subscription", "field_paths": ["listen"]}
}

# Introspection blocked
test_introspection_blocked if {
	deny["introspection queries are blocked"] with input as {"depth": 1, "field_count": 1, "operation_type": "query", "field_paths": ["__schema"], "operation_name": "IntrospectionQuery"}
}

# Cost: within budget
test_cost_allow if {
	allow with input as {"depth": 3, "field_count": 3, "operation_type": "query", "field_paths": ["a", "a.b", "a.b.c"]}
}

# Cost: over budget
test_cost_block if {
	deny[msg] with input as {"depth": 20, "field_count": 10, "operation_type": "query", "field_paths": ["a"]}
	startswith(msg, "query cost")
}

