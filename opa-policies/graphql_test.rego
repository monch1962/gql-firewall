# OPA Rego policy tests for the GraphQL firewall.
# Covers OWASP Top 10 for GraphQL and common attack vectors.
# Run: opa test opa-policies/
package graphql

# ===========================================================================
# ATTACK 1: Introspection Abuse
# ===========================================================================
test_introspection_named_blocked if {
	deny["introspection queries are blocked"] with input as {
		"depth": 1, "field_count": 1, "operation_type": "query",
		"field_paths": ["__schema"], "operation_name": "IntrospectionQuery"
	}
}

test_introspection_schema_field_blocked if {
	deny[msg] with input as {
		"depth": 1, "field_count": 1, "operation_type": "query",
		"field_paths": ["__schema"]
	}
	startswith(msg, "introspection field")
}

test_introspection_type_field_blocked if {
	deny[msg] with input as {
		"depth": 1, "field_count": 1, "operation_type": "query",
		"field_paths": ["__type"]
	}
	startswith(msg, "introspection field")
}

test_introspection_typename_field_blocked if {
	deny[msg] with input as {
		"depth": 2, "field_count": 2, "operation_type": "query",
		"field_paths": ["user", "user.__typename"]
	}
	startswith(msg, "introspection field")
}

test_non_introspection_allowed if {
	allow with input as {
		"depth": 1, "field_count": 1, "operation_type": "query",
		"field_paths": ["user.name"], "operation_name": "GetUser"
	}
}

# ===========================================================================
# ATTACK 2: Depth-based DoS
# ===========================================================================
test_depth_under_limit_allowed if {
	allow with input as {
		"depth": 5, "field_count": 3, "operation_type": "query",
		"field_paths": ["user", "user.name", "user.email"]
	}
}

test_depth_at_limit_allowed if {
	allow with input as {
		"depth": 10, "field_count": 3, "operation_type": "query",
		"field_paths": ["a", "a.b", "a.b.c"]
	}
}

test_depth_over_limit_blocked if {
	deny[msg] with input as {
		"depth": 20, "field_count": 3, "operation_type": "query",
		"field_paths": ["user", "user.name"]
	}
	startswith(msg, "query depth 20")
}

# ===========================================================================
# ATTACK 3: Alias-based DoS (Billion Laughs)
# ===========================================================================
test_alias_bomb_blocked if {
	deny[msg] with input as {
		"depth": 2, "field_count": 150, "operation_type": "query",
		"field_paths": ["a1.user.name", "a2.user.name", "a3.user.name"]
	}
	contains(msg, "alias bomb")
}

test_normal_field_count_allowed if {
	allow with input as {
		"depth": 2, "field_count": 5, "operation_type": "query",
		"field_paths": ["user", "user.name", "user.email", "posts", "posts.title"]
	}
}

# ===========================================================================
# ATTACK 4: Directive-based DoS
# ===========================================================================
test_directive_limit_respected if {
	allow with input as {
		"depth": 1, "field_count": 1, "operation_type": "query",
		"field_paths": ["hello"], "directives": 3
	}
}

test_directive_bomb_blocked if {
	deny[msg] with input as {
		"depth": 1, "field_count": 1, "operation_type": "query",
		"field_paths": ["hello"], "directives": 50
	}
	contains(msg, "directive count")
}

# ===========================================================================
# ATTACK 5: Batching Attack
# ===========================================================================
test_single_batch_allowed if {
	allow with input as {
		"depth": 1, "field_count": 1, "operation_type": "query",
		"field_paths": ["hello"], "batch_size": 1
	}
}

test_multi_batch_blocked if {
	deny[msg] with input as {
		"depth": 1, "field_count": 1, "operation_type": "query",
		"field_paths": ["hello"], "batch_size": 5
	}
	contains(msg, "batch size")
}

# ===========================================================================
# ATTACK 6: Unauthorized Field Access
# ===========================================================================
test_safe_field_allowed if {
	allow with input as {
		"depth": 1, "field_count": 1, "operation_type": "query",
		"field_paths": ["user.name"]
	}
}

test_ssn_blocked if {
	deny[msg] with input as {
		"depth": 2, "field_count": 2, "operation_type": "query",
		"field_paths": ["user", "user.ssn"]
	}
	contains(msg, "user.ssn")
}

test_password_blocked if {
	deny[msg] with input as {
		"depth": 2, "field_count": 2, "operation_type": "query",
		"field_paths": ["user", "user.password"]
	}
	contains(msg, "user.password")
}

test_credit_card_blocked if {
	deny[msg] with input as {
		"depth": 2, "field_count": 2, "operation_type": "query",
		"field_paths": ["user", "user.creditCard"]
	}
	contains(msg, "user.creditCard")
}

test_admin_secret_blocked if {
	deny[msg] with input as {
		"depth": 2, "field_count": 2, "operation_type": "query",
		"field_paths": ["admin", "admin.secretKey"]
	}
	contains(msg, "admin.secretKey")
}

# Field allowlist enforcement
test_allowlist_field_allowed if {
	allow with input as {
		"depth": 1, "field_count": 1, "operation_type": "query",
		"field_paths": ["user.name"], "field_allowlist": ["user.name"]
	}
}

test_allowlist_field_blocked if {
	deny[msg] with input as {
		"depth": 2, "field_count": 2, "operation_type": "query",
		"field_paths": ["user", "user.ssn"], "field_allowlist": ["user.name", "user.email"]
	}
	contains(msg, "allowlist")
}

# ===========================================================================
# ATTACK 7: Mutation Abuse
# ===========================================================================
test_query_allowed if {
	allow with input as {
		"depth": 1, "field_count": 1, "operation_type": "query",
		"field_paths": ["hello"]
	}
}

test_mutation_allowed if {
	allow with input as {
		"depth": 1, "field_count": 1, "operation_type": "mutation",
		"field_paths": ["createUser"]
	}
}

test_subscription_blocked if {
	deny["subscriptions are not allowed"] with input as {
		"depth": 1, "field_count": 1, "operation_type": "subscription",
		"field_paths": ["onMessage"]
	}
}

# ===========================================================================
# ATTACK 8: Argument Depth Attack
# ===========================================================================
test_shallow_args_allowed if {
	allow with input as {
		"depth": 1, "field_count": 1, "operation_type": "query",
		"field_paths": ["user"], "argument_depth": 2
	}
}

test_deep_args_blocked if {
	deny[msg] with input as {
		"depth": 1, "field_count": 1, "operation_type": "query",
		"field_paths": ["user"], "argument_depth": 20
	}
	contains(msg, "argument depth")
}

# ===========================================================================
# ATTACK 9: N+1 Abuse / List Overload
# ===========================================================================
test_few_lists_allowed if {
	allow with input as {
		"depth": 2, "field_count": 3, "operation_type": "query",
		"field_paths": ["users", "users.name"], "lists_requested": 1
	}
}

test_too_many_lists_blocked if {
	deny[msg] with input as {
		"depth": 2, "field_count": 3, "operation_type": "query",
		"field_paths": ["users", "users.name"], "lists_requested": 20
	}
	contains(msg, "list fields")
}

# ===========================================================================
# ATTACK 10: Fragment Explosion
# ===========================================================================
test_few_fragments_allowed if {
	allow with input as {
		"depth": 2, "field_count": 3, "operation_type": "query",
		"field_paths": ["user", "user.name"], "fragment_spread_count": 3
	}
}

test_too_many_fragments_blocked if {
	deny[msg] with input as {
		"depth": 2, "field_count": 3, "operation_type": "query",
		"field_paths": ["user", "user.name"], "fragment_spread_count": 50
	}
	contains(msg, "fragment spread")
}

# ===========================================================================
# ATTACK 11: Query Cost Analysis
# ===========================================================================
test_cost_within_budget if {
	allow with input as {
		"depth": 3, "field_count": 3, "operation_type": "query",
		"field_paths": ["a", "a.b", "a.b.c"]
	}
}

test_cost_over_budget if {
	deny[msg] with input as {
		"depth": 20, "field_count": 10, "operation_type": "query",
		"field_paths": ["a"]
	}
	startswith(msg, "query cost")
}

# ===========================================================================
# ATTACK 12: Persisted Query Bypass
# ===========================================================================
test_dynamic_query_allowed_when_not_required if {
	allow with input as {
		"depth": 1, "field_count": 1, "operation_type": "query",
		"field_paths": ["hello"], "require_persisted_queries": false
	}
}

test_dynamic_query_blocked_when_required if {
	deny["dynamic queries are not allowed"] with input as {
		"depth": 1, "field_count": 1, "operation_type": "query",
		"field_paths": ["hello"], "require_persisted_queries": true
	}
}

# ===========================================================================
# Sanity: no rules configured = pass-through
# ===========================================================================
test_no_extra_denies if {
	count(deny) == 0 with input as {
		"depth": 1, "field_count": 1, "operation_type": "query",
		"field_paths": ["hello"]
	}
}
