package opa

import (
	"os"
	"strings"
	"testing"
)

// loadProductionPolicy loads the actual opa-policies/graphql.rego file.
func loadProductionPolicy(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../opa-policies/graphql.rego")
	if err != nil {
		t.Fatalf("loading production policy: %v", err)
	}
	return string(data)
}

// defaultParams are realistic parameters that match the production defaults.
var defaultParams = map[string]interface{}{
	"depth_limit":               10.0,
	"max_field_count":           100.0,
	"max_directives":            5.0,
	"max_batch_size":            1.0,
	"max_argument_depth":        5.0,
	"max_lists_requested":       5.0,
	"max_fragment_spreads":      15.0,
	"cost_budget":               50.0,
	"require_persisted_queries": false,
}

// newOWASPEval creates an embedded evaluator with the production policy and given params.
func newOWASPEval(t *testing.T, params map[string]interface{}, tenants ...struct {
	id  string
	cfg map[string]interface{}
}) *EmbeddedEvaluator {
	t.Helper()
	store := NewDataStore()
	store.SetParams(params)
	for _, tnt := range tenants {
		store.SetTenant(tnt.id, tnt.cfg)
	}
	e, err := NewEmbedded(EmbedConfig{
		Policy: loadProductionPolicy(t),
		Store:  store,
	})
	if err != nil {
		t.Fatalf("creating embedded evaluator: %v", err)
	}
	return e
}

// assertBlocked checks that the evaluator blocks the given input with a reason containing substr.
func assertBlocked(t *testing.T, e *EmbeddedEvaluator, input *Input, substr string) {
	t.Helper()
	result, err := e.Evaluate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Errorf("expected blocked (substr=%q), got allowed", substr)
	} else if substr != "" && !strings.Contains(result.Reason, substr) {
		t.Errorf("expected reason to contain %q, got %q", substr, result.Reason)
	}
}

// assertAllowed checks that the evaluator allows the given input.
func assertAllowed(t *testing.T, e *EmbeddedEvaluator, input *Input) {
	t.Helper()
	result, err := e.Evaluate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed, got blocked: %s", result.Reason)
	}
}

// copyMap returns a shallow copy of a map.
func copyMap(m map[string]interface{}) map[string]interface{} {
	cp := make(map[string]interface{}, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

// =============================================================================
// ATTACK 1: Introspection Abuse
// =============================================================================

func TestOWASP_Introspection_NamedQueryBlocked(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query",
		Depth:         1, FieldCount: 1,
		FieldPaths:    []string{"hello"},
		OperationName: "IntrospectionQuery",
		Params:        defaultParams,
	}
	assertBlocked(t, e, input, "introspection queries are blocked")
}

func TestOWASP_Introspection_SchemaFieldBlocked(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 1, FieldCount: 1,
		FieldPaths: []string{"__schema"},
		Params:     defaultParams,
	}
	assertBlocked(t, e, input, "introspection field")
}

func TestOWASP_Introspection_TypeFieldBlocked(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 1, FieldCount: 1,
		FieldPaths: []string{"__type"},
		Params:     defaultParams,
	}
	assertBlocked(t, e, input, "introspection field")
}

func TestOWASP_Introspection_NestedTypenameBlocked(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 2, FieldCount: 2,
		FieldPaths: []string{"user", "user.__typename"},
		Params:     defaultParams,
	}
	assertBlocked(t, e, input, "introspection field")
}

func TestOWASP_Introspection_AllowedQueryPasses(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 1, FieldCount: 1,
		OperationName: "GetUser",
		FieldPaths:    []string{"user.name"},
		Params:        defaultParams,
	}
	assertAllowed(t, e, input)
}

// =============================================================================
// ATTACK 2: Depth-based DoS
// =============================================================================

func TestOWASP_DepthDoS_DeepQueryBlocked(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 20, FieldCount: 2,
		FieldPaths: []string{"a", "a.b"},
		Params:     defaultParams,
	}
	assertBlocked(t, e, input, "query depth")
}

func TestOWASP_DepthDoS_ShallowQueryPasses(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 5, FieldCount: 3,
		FieldPaths: []string{"user", "user.name"},
		Params:     defaultParams,
	}
	assertAllowed(t, e, input)
}

func TestOWASP_DepthDoS_AtLimitPasses(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 10, FieldCount: 3,
		FieldPaths: []string{"a", "a.b", "a.b.c"},
		Params:     defaultParams,
	}
	assertAllowed(t, e, input)
}

// =============================================================================
// ATTACK 3: Alias-based DoS (Billion Laughs)
// =============================================================================

func TestOWASP_AliasDoS_HighFieldCountBlocked(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 2, FieldCount: 150,
		FieldPaths: []string{"a1.user", "a2.user"},
		Params:     defaultParams,
	}
	assertBlocked(t, e, input, "alias bomb")
}

func TestOWASP_AliasDoS_NormalFieldCountPasses(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 2, FieldCount: 5,
		FieldPaths: []string{"user", "user.name", "user.email"},
		Params:     defaultParams,
	}
	assertAllowed(t, e, input)
}

// =============================================================================
// ATTACK 4: Directive-based DoS
// =============================================================================

func TestOWASP_DirectiveDoS_HighCountBlocked(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 1, FieldCount: 1,
		FieldPaths:  []string{"hello"},
		Directives:  50,
		Params:      defaultParams,
	}
	assertBlocked(t, e, input, "directive count")
}

func TestOWASP_DirectiveDoS_NormalCountPasses(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 1, FieldCount: 1,
		FieldPaths:  []string{"hello"},
		Directives:  3,
		Params:      defaultParams,
	}
	assertAllowed(t, e, input)
}

// =============================================================================
// ATTACK 5: Batching Attack
// =============================================================================

func TestOWASP_Batching_MultiOpBlocked(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 1, FieldCount: 1,
		FieldPaths: []string{"hello"},
		BatchSize:  5,
		Params:     defaultParams,
	}
	assertBlocked(t, e, input, "batch size")
}

func TestOWASP_Batching_SingleOpPasses(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 1, FieldCount: 1,
		FieldPaths: []string{"hello"},
		BatchSize:  1,
		Params:     defaultParams,
	}
	assertAllowed(t, e, input)
}

// =============================================================================
// ATTACK 6: Unauthorized Field Access
// =============================================================================

func TestOWASP_FieldAccess_BlockedFieldBlocked(t *testing.T) {
	params := copyMap(defaultParams)
	params["field_blocklist"] = []interface{}{"user.ssn", "user.password"}
	e := newOWASPEval(t, params)
	input := &Input{
		OperationType: "query", Depth: 2, FieldCount: 2,
		FieldPaths: []string{"user", "user.ssn"},
		Params:     params,
	}
	assertBlocked(t, e, input, "user.ssn")
}

func TestOWASP_FieldAccess_SafeFieldPasses(t *testing.T) {
	params := copyMap(defaultParams)
	params["field_blocklist"] = []interface{}{"user.ssn", "user.password"}
	e := newOWASPEval(t, params)
	input := &Input{
		OperationType: "query", Depth: 2, FieldCount: 2,
		FieldPaths: []string{"user", "user.name"},
		Params:     params,
	}
	assertAllowed(t, e, input)
}

func TestOWASP_FieldAccess_AllowlistBlocksNonListed(t *testing.T) {
	params := copyMap(defaultParams)
	params["field_allowlist"] = []interface{}{"user.name", "user.email"}
	e := newOWASPEval(t, params)
	input := &Input{
		OperationType: "query", Depth: 2, FieldCount: 2,
		FieldPaths: []string{"user", "user.ssn"},
		Params:     params,
	}
	assertBlocked(t, e, input, "allowlist")
}

func TestOWASP_FieldAccess_AllowlistAllowsListed(t *testing.T) {
	params := copyMap(defaultParams)
	params["field_allowlist"] = []interface{}{"user", "user.name", "user.email"}
	e := newOWASPEval(t, params)
	input := &Input{
		OperationType: "query", Depth: 2, FieldCount: 2,
		FieldPaths: []string{"user", "user.name"},
		Params:     params,
	}
	assertAllowed(t, e, input)
}

// =============================================================================
// ATTACK 7: Operation Type Abuse
// =============================================================================

func TestOWASP_OpType_SubscriptionBlocked(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "subscription", Depth: 1, FieldCount: 1,
		FieldPaths: []string{"onMessage"},
		Params:     defaultParams,
	}
	// Without blocked_operations being set, subscriptions are allowed by default.
	assertAllowed(t, e, input)
}

func TestOWASP_OpType_BlockedOpTypeBlocked(t *testing.T) {
	params := copyMap(defaultParams)
	params["blocked_operations"] = []interface{}{"subscription"}
	e := newOWASPEval(t, params)
	input := &Input{
		OperationType: "subscription", Depth: 1, FieldCount: 1,
		FieldPaths: []string{"onMessage"},
		Params:     params,
	}
	assertBlocked(t, e, input, "blocked")
}

func TestOWASP_OpType_QueryAllowed(t *testing.T) {
	params := copyMap(defaultParams)
	params["blocked_operations"] = []interface{}{"subscription"}
	e := newOWASPEval(t, params)
	input := &Input{
		OperationType: "query", Depth: 1, FieldCount: 1,
		FieldPaths: []string{"hello"},
		Params:     params,
	}
	assertAllowed(t, e, input)
}

func TestOWASP_OpType_AllowedOpsEnforced(t *testing.T) {
	params := copyMap(defaultParams)
	params["allowed_operations"] = []interface{}{"query", "mutation"}
	e := newOWASPEval(t, params)
	input := &Input{
		OperationType: "subscription", Depth: 1, FieldCount: 1,
		FieldPaths: []string{"onMessage"},
		Params:     params,
	}
	assertBlocked(t, e, input, "not allowed")
}

// =============================================================================
// ATTACK 8: Argument Injection / Argument Depth
// =============================================================================

func TestOWASP_ArgDepth_DeepArgsBlocked(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 1, FieldCount: 1,
		FieldPaths:    []string{"user"},
		ArgumentDepth: 20,
		Params:        defaultParams,
	}
	assertBlocked(t, e, input, "argument depth")
}

func TestOWASP_ArgDepth_ShallowArgsPasses(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 1, FieldCount: 1,
		FieldPaths:    []string{"user"},
		ArgumentDepth: 2,
		Params:        defaultParams,
	}
	assertAllowed(t, e, input)
}

// =============================================================================
// ATTACK 9: N+1 Abuse
// =============================================================================

func TestOWASP_NPlusOne_TooManyListsBlocked(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 2, FieldCount: 3,
		FieldPaths:    []string{"users", "users.name"},
		ListsRequested: 20,
		Params:         defaultParams,
	}
	assertBlocked(t, e, input, "list fields")
}

func TestOWASP_NPlusOne_FewListsPasses(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 2, FieldCount: 3,
		FieldPaths:    []string{"users", "users.name"},
		ListsRequested: 1,
		Params:         defaultParams,
	}
	assertAllowed(t, e, input)
}

// =============================================================================
// ATTACK 10: Fragment Explosion
// =============================================================================

func TestOWASP_FragmentExplosion_HighCountBlocked(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType:      "query", Depth: 2, FieldCount: 3,
		FieldPaths:          []string{"user", "user.name"},
		FragmentSpreadCount: 50,
		Params:              defaultParams,
	}
	assertBlocked(t, e, input, "fragment spread")
}

func TestOWASP_FragmentExplosion_LowCountPasses(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType:      "query", Depth: 2, FieldCount: 3,
		FieldPaths:          []string{"user", "user.name"},
		FragmentSpreadCount: 3,
		Params:              defaultParams,
	}
	assertAllowed(t, e, input)
}

// =============================================================================
// ATTACK 11: Query Cost Analysis
// =============================================================================

func TestOWASP_QueryCost_HighCostBlocked(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 20, FieldCount: 10,
		FieldPaths: []string{"a"},
		Params:     defaultParams,
	}
	assertBlocked(t, e, input, "query cost")
}

func TestOWASP_QueryCost_LowCostPasses(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 3, FieldCount: 3,
		FieldPaths: []string{"a", "a.b", "a.b.c"},
		Params:     defaultParams,
	}
	assertAllowed(t, e, input)
}

// =============================================================================
// ATTACK 12: Persisted Query Bypass
// =============================================================================

func TestOWASP_PersistedQuery_DynamicBlockedWhenRequired(t *testing.T) {
	params := copyMap(defaultParams)
	params["require_persisted_queries"] = true
	e := newOWASPEval(t, params)
	input := &Input{
		OperationType: "query", Depth: 1, FieldCount: 1,
		FieldPaths: []string{"hello"},
		Params:     params,
	}
	assertBlocked(t, e, input, "dynamic queries are not allowed")
}

func TestOWASP_PersistedQuery_DynamicAllowedWhenNotRequired(t *testing.T) {
	e := newOWASPEval(t, defaultParams)
	input := &Input{
		OperationType: "query", Depth: 1, FieldCount: 1,
		FieldPaths: []string{"hello"},
		Params:     defaultParams,
	}
	assertAllowed(t, e, input)
}

func TestOWASP_PersistedQuery_PersistedWithHashPasses(t *testing.T) {
	params := copyMap(defaultParams)
	params["require_persisted_queries"] = true
	e := newOWASPEval(t, params)
	input := &Input{
		OperationType:  "query", Depth: 1, FieldCount: 1,
		OperationName:  "GetUser",
		FieldPaths:     []string{"hello"},
		QueryHash:      "a1b2c3d4",
		Params:         params,
	}
	assertAllowed(t, e, input)
}

// =============================================================================
// Tenant overrides
// =============================================================================

func TestOWASP_Tenant_TighterDepthLimitEnforced(t *testing.T) {
	e := newOWASPEval(t, defaultParams, struct {
		id  string
		cfg map[string]interface{}
	}{"strict", map[string]interface{}{"depth_limit": 3.0}})
	input := &Input{
		OperationType: "query", Depth: 5, FieldCount: 3,
		FieldPaths: []string{"hello"},
		TenantID:   "strict",
		Params:     defaultParams,
		TenantConfig: map[string]interface{}{"depth_limit": 3.0},
	}
	assertBlocked(t, e, input, "tenant depth limit")
}

func TestOWASP_Tenant_NonTenantUsesGlobal(t *testing.T) {
	e := newOWASPEval(t, defaultParams, struct {
		id  string
		cfg map[string]interface{}
	}{"strict", map[string]interface{}{"depth_limit": 3.0}})
	input := &Input{
		OperationType: "query", Depth: 5, FieldCount: 3,
		FieldPaths: []string{"hello"},
		Params:     defaultParams,
	}
	assertAllowed(t, e, input)
}

func TestOWASP_Tenant_BlockedFieldEnforced(t *testing.T) {
	e := newOWASPEval(t, defaultParams, struct {
		id  string
		cfg map[string]interface{}
	}{"corp", map[string]interface{}{"field_blocklist": []interface{}{"admin.secret"}}})
	input := &Input{
		OperationType: "query", Depth: 2, FieldCount: 2,
		FieldPaths:   []string{"admin", "admin.secret"},
		TenantID:     "corp",
		Params:       defaultParams,
		TenantConfig: map[string]interface{}{"field_blocklist": []interface{}{"admin.secret"}},
	}
	assertBlocked(t, e, input, "blocked by tenant policy")
}

// =============================================================================
// Negative: attack that doesn't match its param should pass
// =============================================================================

func TestOWASP_Negative_DeepQueryWhenParamNotSet(t *testing.T) {
	// Remove all budget-related params so no deny rule fires
	params := copyMap(defaultParams)
	delete(params, "depth_limit")
	delete(params, "cost_budget")
	e := newOWASPEval(t, params)
	input := &Input{
		OperationType: "query", Depth: 100, FieldCount: 3,
		FieldPaths: []string{"a"},
		Params:     params,
	}
	assertAllowed(t, e, input)
}

func TestOWASP_Negative_HighDirectivesWhenParamNotSet(t *testing.T) {
	params := copyMap(defaultParams)
	delete(params, "max_directives")
	e := newOWASPEval(t, params)
	input := &Input{
		OperationType: "query", Depth: 1, FieldCount: 1,
		FieldPaths:  []string{"hello"},
		Directives:  999,
		Params:      params,
	}
	assertAllowed(t, e, input)
}

func TestOWASP_Negative_EmptyBlocklistBlocksNothing(t *testing.T) {
	params := copyMap(defaultParams)
	params["field_blocklist"] = []interface{}{}
	e := newOWASPEval(t, params)
	input := &Input{
		OperationType: "query", Depth: 1, FieldCount: 1,
		FieldPaths: []string{"user.ssn"},
		Params:     params,
	}
	assertAllowed(t, e, input)
}
