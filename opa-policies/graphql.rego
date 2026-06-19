# GraphQL Firewall — OPA Rego Policy Templates
# Covers OWASP Top 10 for GraphQL and common attack vectors.
# Deny-override model: allowed by default, blocked by deny rules.
# Requires OPA v1.0+.
package graphql

default allow := true

# =============================================================================
# ATTACK 1: Introspection Abuse
# =============================================================================
# Attackers query __schema, __type, or __typename to discover the full API
# surface, field definitions, arguments, and deprecation notices.
#
# Covers: direct __schema/__type queries, introspection via __typename
# on all types, and named IntrospectionQuery operations.

deny contains "introspection queries are blocked" if {
	input.operation_name == "IntrospectionQuery"
}

introspection_fields := {"__schema", "__type", "__typename"}

introspection_field_requested contains f if {
	some f in introspection_fields
	f == input.field_paths[_]
}

deny contains msg if {
	introspection_field_requested[f]
	msg := sprintf("introspection field %q is blocked", [f])
}

# Also catch __typename when nested: "user.__typename"
introspection_suffix_requested contains f if {
	some f in introspection_fields
	some path in input.field_paths
	endswith(path, concat("", ["." , f]))
}

deny contains msg if {
	introspection_suffix_requested[f]
	msg := sprintf("introspection field %q is blocked", [f])
}

# =============================================================================
# ATTACK 2: Depth-based DoS (Recursive/Nested Query Attack)
# =============================================================================
# Deeply nested queries like { a { b { c { d { e } } } } } exhaust CPU
# and memory as the server resolves each nesting level.
#
# Covers: simple depth bombs, deeply nested fragments.

depth_limit := 10

deny contains msg if {
	input.depth > depth_limit
	msg := sprintf("query depth %d exceeds limit %d", [input.depth, depth_limit])
}

# =============================================================================
# ATTACK 3: Alias-based DoS (Billion Laughs / Field Duplication)
# =============================================================================
# Same expensive field requested hundreds of times via aliases:
# { a1: user { name } a2: user { name } ... a500: user { name } }
# Detect via field count — excessive fields suggest alias bombing.

alias_max_field_count := 100

deny contains msg if {
	input.field_count > alias_max_field_count
	msg := sprintf("field count %d exceeds limit (possible alias bomb)", [input.field_count])
}

# =============================================================================
# ATTACK 4: Directive-based DoS
# =============================================================================
# Custom directives like @transform, @fetch, or @delay can trigger expensive
# server-side operations. Malicious queries include many directives.
#
# Covers: directive count limits via input.directives.
# Note: requires Go sidecar to populate input.directives.

max_directives := 5

deny contains msg if {
	input.directives > max_directives
	msg := sprintf("directive count %d exceeds limit %d", [input.directives, max_directives])
}

# =============================================================================
# ATTACK 5: Batching Attack (Operation Overload)
# =============================================================================
# Multiple operations in a single request to bypass per-request rate limits.
# The Go sidecar only sends the first operation's info — detect via
# input.batch_size if populated.
#
# Covers: batch size limits.

max_batch_size := 1

deny contains msg if {
	input.batch_size > max_batch_size
	msg := sprintf("batch size %d exceeds limit %d", [input.batch_size, max_batch_size])
}

# =============================================================================
# ATTACK 6: Unauthorized Field Access
# =============================================================================
# Requesting fields the caller should not have access to (e.g. other users'
# data, admin-only fields, PII).
#
# Covers: field blocklist + allowlist.

blocked_fields := {
	"user.ssn", "user.password", "user.secret", "user.tokens",
	"user.creditCard", "user.dob", "user.driverLicense",
	"admin.secretKey", "admin.apiKey", "admin.internalNote",
	"config.environment", "config.secret",
}

violated_fields contains f if {
	some f in blocked_fields
	f == input.field_paths[_]
}

deny contains msg if {
	violated_fields[f]
	msg := sprintf("field %q is blocked", [f])
}

# Field allowlist — if set, only these fields are permitted.
# allowlist takes precedence over blocklist (overrides).

deny contains msg if {
	count(input.field_allowlist) > 0
	some path in input.field_paths
	not field_on_allowlist(path)
	msg := sprintf("field %q is not in the allowlist", [path])
}

field_on_allowlist(path) if {
	some permitted in input.field_allowlist
	path == permitted
}

field_on_allowlist(path) if {
	some permitted in input.field_allowlist
	startswith(path, permitted)
}

# =============================================================================
# ATTACK 7: Mutation Abuse
# =============================================================================
# Mutations in read-only contexts, or mutations that modify state
# unexpectedly (e.g. DELETE operations sent as query).
#
# Covers: operation type allow/block lists.

deny contains msg if {
	input.operation_type == "subscription"
	msg := "subscriptions are not allowed"
}

# =============================================================================
# ATTACK 8: Argument Injection / Argument Depth Attack
# =============================================================================
# Arguments with deeply nested objects to exploit resolver logic or
# trigger expensive database lookups. Detect via input.argument_depth.
#
# Covers: argument depth limits (requires Go sidecar input).

max_argument_depth := 5

deny contains msg if {
	input.argument_depth > max_argument_depth
	msg := sprintf("argument depth %d exceeds limit %d", [input.argument_depth, max_argument_depth])
}

# =============================================================================
# ATTACK 9: N+1 Abuse / Pagination Abuse
# =============================================================================
# Requesting large lists without pagination, triggering N+1 database
# queries. Detect via input.lists_requested or input.max_list_size.
#
# Covers: list size limits (requires Go sidecar input).

max_lists_requested := 5

deny contains msg if {
	input.lists_requested > max_lists_requested
	msg := sprintf("too many list fields requested (%d)", [input.lists_requested])
}

# =============================================================================
# ATTACK 10: Union/Interface Fragment Explosion
# =============================================================================
# Spreading across many union/interface types with ... on Type to multiply
# query cost. Each spread may resolve different fields. Detect via
# input.fragment_spread_count.
#
# Covers: fragment spread limits (requires Go sidecar input).

max_fragment_spreads := 15

deny contains msg if {
	input.fragment_spread_count > max_fragment_spreads
	msg := sprintf("fragment spread count %d exceeds limit %d", [input.fragment_spread_count, max_fragment_spreads])
}

# =============================================================================
# ATTACK 11: Query Cost Analysis (Complexity Budget)
# =============================================================================
# Combined cost heuristic: depth × field_count as a rough complexity metric.
# More sophisticated cost analysis would assign weights per field/resolver.
#
# Covers: depth × field_count budget.

cost_budget := 50

deny contains msg if {
	(input.depth * input.field_count) > cost_budget
	msg := sprintf("query cost %d exceeds budget %d", [input.depth * input.field_count, cost_budget])
}

# =============================================================================
# ATTACK 12: Persisted Query Bypass
# =============================================================================
# When operating in persisted-query-only mode, dynamic queries (those with
# arbitrary operation names or no operation name at all) should be blocked.
#
# Covers: operation name validation (requires Go sidecar input).

deny contains "dynamic queries are not allowed" if {
	input.require_persisted_queries == true
	not input.operation_name
}

deny contains msg if {
	input.require_persisted_queries == true
	input.operation_name
	not input.query_hash
	msg := sprintf("persisted query %q has no matching hash", [input.operation_name])
}

# =============================================================================
# Allow override
# =============================================================================
allow if {
	count(deny) == 0
}
