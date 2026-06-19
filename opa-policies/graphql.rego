# GraphQL Firewall — OPA Rego Policy Templates
# Uses deny-override model: allowed by default, blocked by deny rules.
# Requires OPA v1.0+ (uses `if` keyword syntax).
package graphql

default allow := true

# Depth limit
depth_limit := 10

deny contains "query exceeds depth limit" if {
	input.depth > depth_limit
}

# Introspection block
deny contains "introspection queries are blocked" if {
	input.operation_name == "IntrospectionQuery"
}

# Field blocklist
blocked_fields := {"__schema", "__type", "__typename", "user.ssn", "user.password", "user.secret"}

violated_fields contains f if {
	some f in blocked_fields
	f == input.field_paths[_]
}

deny contains "blocked field requested" if {
	count(violated_fields) > 0
}

# Operation type restrictions — subscriptions not allowed
deny contains "subscriptions are not allowed" if {
	input.operation_type == "subscription"
}

# Cost budget: depth * field_count must not exceed budget
cost_budget := 50

deny contains msg if {
	(input.depth * input.field_count) > cost_budget
	msg := sprintf("query cost %d exceeds budget %d", [input.depth * input.field_count, cost_budget])
}

# Allow override: deny decisions are final, but this ensures the system
# returns allow=true when no deny rules fire.
allow if {
	count(deny) == 0
}
