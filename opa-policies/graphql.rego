# GraphQL Firewall — OPA Rego Policies
# Covers OWASP Top 10 for GraphQL and common attack vectors.
# Deny-override model: allowed by default, blocked by deny rules.
# Parameters come from input.params (populated by Go sidecar).
# Tenant overrides come from input.tenant_config (populated per-tenant).
package graphql

default allow := false

allow if {
    count(deny) == 0
}

# =============================================================================
# ATTACK 1: Introspection Abuse (OWASP API8 — Injection)
# =============================================================================
# Attackers query __schema, __type, or __typename to discover the full API
# surface, field definitions, arguments, and deprecation notices.

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
    endswith(path, concat("", [".", f]))
}

deny contains msg if {
    introspection_suffix_requested[f]
    msg := sprintf("introspection field %q is blocked", [f])
}

# =============================================================================
# ATTACK 2: Depth-based DoS (OWASP API4 — Mass Assignment)
# =============================================================================
# Deeply nested queries like { a { b { c { d { e } } } } } exhaust CPU
# and memory as the server resolves each nesting level.
# Parameter: input.params.depth_limit (default 10).

deny contains msg if {
    input.depth > input.params.depth_limit
    msg := sprintf("query depth %d exceeds limit %v", [input.depth, input.params.depth_limit])
}

# =============================================================================
# ATTACK 3: Alias-based DoS (Billion Laughs / Field Duplication)
# =============================================================================
# Same expensive field requested hundreds of times via aliases.
# Detect via field count — excessive fields suggest alias bombing.
# Parameter: input.params.max_field_count (default 100).

deny contains msg if {
    input.field_count > input.params.max_field_count
    msg := sprintf("field count %d exceeds limit (possible alias bomb)", [input.field_count])
}

# =============================================================================
# ATTACK 4: Directive-based DoS
# =============================================================================
# Custom directives like @transform, @fetch, or @delay can trigger expensive
# server-side operations.
# Parameter: input.params.max_directives (default 5).

deny contains msg if {
    input.params.max_directives
    input.directives > input.params.max_directives
    msg := sprintf("directive count %d exceeds limit %v", [input.directives, input.params.max_directives])
}

# =============================================================================
# ATTACK 5: Batching Attack (Operation Overload)
# =============================================================================
# Multiple operations in a single request to bypass per-request rate limits.
# Parameter: input.params.max_batch_size (default 1).

deny contains msg if {
    input.params.max_batch_size
    input.batch_size > input.params.max_batch_size
    msg := sprintf("batch size %d exceeds limit %v", [input.batch_size, input.params.max_batch_size])
}

# =============================================================================
# ATTACK 6: Unauthorized Field Access (OWASP API3 — Excessive Data Exposure)
# =============================================================================
# Requesting fields the caller should not have access to (PII, secrets, admin).
# Parameter: input.params.field_blocklist (array of dot-separated paths).

deny contains msg if {
    some blocked in input.params.field_blocklist
    some path in input.field_paths
    path == blocked
    msg := sprintf("field %q is blocked", [path])
}

# Field allowlist — if set, only these fields are permitted.
deny contains msg if {
    count(input.params.field_allowlist) > 0
    some path in input.field_paths
    not field_on_allowlist(path)
    msg := sprintf("field %q is not in the allowlist", [path])
}

field_on_allowlist(path) if {
    some permitted in input.params.field_allowlist
    path == permitted
}

field_on_allowlist(path) if {
    some permitted in input.params.field_allowlist
    startswith(path, permitted)
}

# =============================================================================
# ATTACK 7: Mutation / Operation Type Abuse
# =============================================================================
# Block specific operation types (e.g., subscriptions in prod).
# Parameter: input.params.blocked_operations (array of operation types).
# Parameter: input.params.allowed_operations (if set, only these are allowed).
# Parameter: input.params.allowed_operation_names (if set, only named ops with
# these names are allowed; unnamed queries are blocked when list is non-empty).

deny contains msg if {
    some blocked in input.params.blocked_operations
    input.operation_type == blocked
    msg := sprintf("operation type %q is blocked", [input.operation_type])
}

deny contains msg if {
    count(input.params.allowed_operations) > 0
    count({op | op = input.params.allowed_operations[_]; op == input.operation_type}) == 0
    msg := sprintf("operation type %q is not allowed", [input.operation_type])
}

# Operation-name allowlist: when set, unnamed operations and operations whose
# name is not in the list are blocked.
deny contains msg if {
    count(input.params.allowed_operation_names) > 0
    input.operation_name == ""
    msg := "anonymous queries are blocked when operation name allowlist is active"
}

deny contains msg if {
    count(input.params.allowed_operation_names) > 0
    input.operation_name != ""
    count({name | name = input.params.allowed_operation_names[_]; name == input.operation_name}) == 0
    msg := sprintf("operation name %q is not in the allowlist", [input.operation_name])
}

# =============================================================================
# ATTACK 8: Argument Injection / Argument Depth Attack
# =============================================================================
# Arguments with deeply nested objects to exploit resolver logic.
# Parameter: input.params.max_argument_depth (default 5).

deny contains msg if {
    input.params.max_argument_depth
    input.argument_depth > input.params.max_argument_depth
    msg := sprintf("argument depth %d exceeds limit %v", [input.argument_depth, input.params.max_argument_depth])
}

# =============================================================================
# ATTACK 9: N+1 Abuse / Pagination Abuse
# =============================================================================
# Requesting large lists without pagination, triggering N+1 database queries.
# Parameter: input.params.max_lists_requested (default 5).

deny contains msg if {
    input.params.max_lists_requested
    input.lists_requested > input.params.max_lists_requested
    msg := sprintf("too many list fields requested (%d)", [input.lists_requested])
}

# =============================================================================
# ATTACK 10: Union/Interface Fragment Explosion
# =============================================================================
# Spreading across many union/interface types with ... on Type to multiply
# query cost.
# Parameter: input.params.max_fragment_spreads (default 15).

deny contains msg if {
    input.params.max_fragment_spreads
    input.fragment_spread_count > input.params.max_fragment_spreads
    msg := sprintf("fragment spread count %d exceeds limit %v", [input.fragment_spread_count, input.params.max_fragment_spreads])
}

# =============================================================================
# ATTACK 11: Query Cost Analysis (Complexity Budget)
# =============================================================================
# Combined cost heuristic: depth × field_count as a rough complexity metric.
# Parameter: input.params.cost_budget (default 50).

deny contains msg if {
    input.params.cost_budget
    (input.depth * input.field_count) > input.params.cost_budget
    msg := sprintf("query cost %d exceeds budget %v", [input.depth * input.field_count, input.params.cost_budget])
}

# =============================================================================
# ATTACK 12: Persisted Query Bypass
# =============================================================================
# When operating in persisted-query-only mode, block dynamic queries.
# Parameter: input.params.require_persisted_queries (default false).

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

# =============================================================================
# Tenant-specific overrides
# =============================================================================
# If the request has a tenant_config, apply tenant-specific rules.
# Tenant config overrides global params for matching fields.

deny contains msg if {
    input.tenant_config
    input.tenant_config.depth_limit
    input.depth > input.tenant_config.depth_limit
    msg := sprintf("tenant depth limit %v exceeded", [input.tenant_config.depth_limit])
}

deny contains msg if {
    input.tenant_config
    input.tenant_config.max_field_count
    input.field_count > input.tenant_config.max_field_count
    msg := sprintf("tenant field count limit %v exceeded", [input.tenant_config.max_field_count])
}

deny contains msg if {
    input.tenant_config
    some blocked in input.tenant_config.field_blocklist
    some path in input.field_paths
    path == blocked
    msg := sprintf("field %q is blocked by tenant policy", [path])
}

deny contains msg if {
    input.tenant_config
    some blocked in input.tenant_config.blocked_operations
    input.operation_type == blocked
    msg := sprintf("operation type %q is blocked by tenant policy", [input.operation_type])
}
