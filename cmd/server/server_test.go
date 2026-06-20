package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/monch1962/gql-firewall/internal/opa"
	"github.com/monch1962/gql-firewall/internal/parser"
	"github.com/monch1962/gql-firewall/internal/rules"
	"github.com/monch1962/gql-firewall/internal/tenant"
)

// newEval is a DRY helper that creates a compositeEvaluator with sensible defaults.
func newEval(opts ...func(*compositeEvaluator)) *compositeEvaluator {
	e := &compositeEvaluator{
		local: &rules.Config{DepthLimit: 10},
		opa:   opa.New(""),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

func withLocal(cfg *rules.Config) func(*compositeEvaluator) {
	return func(e *compositeEvaluator) { e.local = cfg }
}

func withTenant(cfg *rules.Config) func(*compositeEvaluator) {
	return func(e *compositeEvaluator) {
		e.tenants = tenant.New(cfg)
	}
}

func withTenantOverride(id string, cfg *rules.Config) func(*compositeEvaluator) {
	return func(e *compositeEvaluator) {
		if e.tenants == nil {
			e.tenants = tenant.New(&rules.Config{})
		}
		e.tenants.Set(id, cfg)
	}
}

func withOPA(endpoint string) func(*compositeEvaluator) {
	return func(e *compositeEvaluator) { e.opa = opa.New(endpoint) }
}

func withOPAFailClosed() func(*compositeEvaluator) {
	return func(e *compositeEvaluator) { e.opaFailClosed = true }
}

func withCacheTTL(d time.Duration) func(*compositeEvaluator) {
	return func(e *compositeEvaluator) { e.cacheTTL = d }
}

func withSchema(s *parser.SchemaInfo) func(*compositeEvaluator) {
	return func(e *compositeEvaluator) { e.schema = s }
}

func qi(opts ...func(*parser.QueryInfo)) *parser.QueryInfo {
	info := &parser.QueryInfo{
		OperationType: "query",
		Depth:         1,
		FieldCount:    1,
		FieldPaths:    []string{"hello"},
	}
	for _, opt := range opts {
		opt(info)
	}
	return info
}

func depth(n int) func(*parser.QueryInfo) {
	return func(i *parser.QueryInfo) { i.Depth = n }
}

func fieldCount(n int) func(*parser.QueryInfo) {
	return func(i *parser.QueryInfo) { i.FieldCount = n }
}

func paths(p ...string) func(*parser.QueryInfo) {
	return func(i *parser.QueryInfo) { i.FieldPaths = p }
}

func opType(t string) func(*parser.QueryInfo) {
	return func(i *parser.QueryInfo) { i.OperationType = t }
}

func tenantID(id string) func(*parser.QueryInfo) {
	return func(i *parser.QueryInfo) { i.TenantID = id }
}

// =========================================================================
// requireAdminAuth
// =========================================================================

func TestRequireAdminAuth_NoTokenConfigured(t *testing.T) {
	h := requireAdminAuth("", okHandler)
	w := serveGET(h)
	assertStatus(t, w, http.StatusOK)
}

func TestRequireAdminAuth_ValidToken(t *testing.T) {
	h := requireAdminAuth("secret", okHandler)
	w := serveGET(h, withHeader("Authorization", "Bearer secret"))
	assertStatus(t, w, http.StatusOK)
}

func TestRequireAdminAuth_MissingToken(t *testing.T) {
	h := requireAdminAuth("secret", failHandler(t))
	w := serveGET(h)
	assertStatus(t, w, http.StatusUnauthorized)
}

func TestRequireAdminAuth_WrongToken(t *testing.T) {
	h := requireAdminAuth("secret", failHandler(t))
	w := serveGET(h, withHeader("Authorization", "Bearer wrong"))
	assertStatus(t, w, http.StatusForbidden)
}

func TestRequireAdminAuth_RawToken(t *testing.T) {
	h := requireAdminAuth("token123", okHandler)
	w := serveGET(h, withHeader("Authorization", "token123"))
	assertStatus(t, w, http.StatusOK)
}

// =========================================================================
// decisionCacheKey
// =========================================================================

func TestDecisionCacheKey_IdenticalInputs(t *testing.T) {
	info := qi(paths("user", "user.name"), depth(3), fieldCount(5))
	k1, k2 := decisionCacheKey(info), decisionCacheKey(info)
	if k1 != k2 {
		t.Errorf("expected identical keys, got %q vs %q", k1, k2)
	}
}

func TestDecisionCacheKey_DifferentPaths(t *testing.T) {
	info1 := qi(paths("user.name"), depth(3), fieldCount(5))
	info2 := qi(paths("user.ssn"), depth(3), fieldCount(5))
	if decisionCacheKey(info1) == decisionCacheKey(info2) {
		t.Error("expected different keys for different field paths")
	}
}

func TestDecisionCacheKey_DifferentOperations(t *testing.T) {
	if decisionCacheKey(qi(opType("query"))) == decisionCacheKey(qi(opType("mutation"))) {
		t.Error("expected different keys for different operation types")
	}
}

// =========================================================================
// simpleHash
// =========================================================================

func TestSimpleHash(t *testing.T) {
	if h := simpleHash([]string{"a", "b", "c"}); h == "" {
		t.Error("expected non-empty hash")
	}
	if simpleHash([]string{"a"}) != simpleHash([]string{"a"}) {
		t.Error("expected consistent hashes")
	}
	if simpleHash([]string{"user.name"}) == simpleHash([]string{"user.ssn"}) {
		t.Error("expected different hashes for different inputs")
	}
	if h := simpleHash(nil); h == "" || h == "00000000" {
		t.Errorf("expected non-zero hash for nil, got %q", h)
	}
}

// =========================================================================
// compositeEvaluator — full path coverage
// =========================================================================

func TestEval_AllowsValidQuery(t *testing.T) {
	result, err := newEval().Evaluate(qi())
	assertAllowed(t, result, err)
}

func TestEval_BlocksDeepQuery(t *testing.T) {
	result, err := newEval().Evaluate(qi(depth(20)))
	assertBlocked(t, result, err, "depth")
}

func TestEval_BlocksBlockedField(t *testing.T) {
	eval := newEval(withLocal(&rules.Config{
		FieldBlocklist: []string{"user.ssn"},
	}))
	result, err := eval.Evaluate(qi(depth(2), fieldCount(2), paths("user", "user.ssn")))
	assertBlocked(t, result, err, "ssn")
}

func TestEval_BlocksDisallowedOperation(t *testing.T) {
	eval := newEval(withLocal(&rules.Config{
		AllowedOperations: []string{"query"},
	}))
	result, err := eval.Evaluate(qi(opType("mutation")))
	assertBlocked(t, result, err, "mutation")
}

func TestEval_TenantOverridesDefault(t *testing.T) {
	eval := newEval(withTenantOverride("strict", &rules.Config{DepthLimit: 5}))
	result, err := eval.Evaluate(qi(tenantID("strict"), depth(20)))
	assertBlocked(t, result, err, "depth")
}

func TestEval_NonTenantGetsDefault(t *testing.T) {
	eval := newEval(withLocal(&rules.Config{}), withTenantOverride("strict", &rules.Config{DepthLimit: 1}))
	result, err := eval.Evaluate(qi(tenantID("other"), depth(20)))
	assertAllowed(t, result, err)
}

func TestEval_TenantAllowsWhenConfigPermits(t *testing.T) {
	eval := newEval(withLocal(&rules.Config{}), withTenantOverride("relaxed", &rules.Config{DepthLimit: 50}))
	result, err := eval.Evaluate(qi(tenantID("relaxed"), depth(20)))
	assertAllowed(t, result, err)
}

func TestEval_SchemaValidationRejects(t *testing.T) {
	// LoadSchemaFromString returns a *SchemaInfo with a valid schema
	schema, err := parser.LoadSchemaFromString(`
		type Query {
			hello: String
		}
		scalar String
		scalar Int
		scalar Float
		scalar Boolean
	`)
	if err != nil {
		t.Fatalf("loading schema: %v", err)
	}
	eval := newEval(withSchema(schema))
	result, err := eval.Evaluate(qi(paths("nonexistent")))
	assertBlocked(t, result, err, "does not exist")
}

func TestEval_SchemaValidationAllows(t *testing.T) {
	schema, err := parser.LoadSchemaFromString(`
		type Query {
			hello: String
		}
		scalar String
		scalar Int
	`)
	if err != nil {
		t.Fatalf("loading schema: %v", err)
	}
	eval := newEval(withSchema(schema))
	result, err := eval.Evaluate(qi(paths("hello")))
	assertAllowed(t, result, err)
}

func TestEval_OPAFailOpenOnError(t *testing.T) {
	// OPA endpoint that doesn't exist should cause error → allow by default
	eval := newEval(withOPA("http://localhost:19999"))
	result, err := eval.Evaluate(qi())
	assertAllowed(t, result, err)
}

func TestEval_OPAFailClosedOnError(t *testing.T) {
	eval := newEval(withOPA("http://localhost:19999"), withOPAFailClosed())
	result, err := eval.Evaluate(qi())
	assertBlocked(t, result, err, "OPA unavailable")
}

func TestEval_OPACacheHit(t *testing.T) {
	// Use a real OPA server that returns allow
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result":{"allowed":true}}`))
	}))
	defer opaSrv.Close()

	eval := newEval(withOPA(opaSrv.URL), withCacheTTL(time.Minute))
	result, err := eval.Evaluate(qi(paths("ping")))
	assertAllowed(t, result, err)

	// Second call with same cache key
	result2, err2 := eval.Evaluate(qi(paths("ping")))
	assertAllowed(t, result2, err2)
}

func TestEval_OPACacheMiss(t *testing.T) {
	callCount := 0
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Write([]byte(`{"result":{"allowed":true}}`))
	}))
	defer opaSrv.Close()

	eval := newEval(withOPA(opaSrv.URL), withCacheTTL(time.Minute))
	eval.Evaluate(qi(paths("first")))
	eval.Evaluate(qi(paths("second"))) // Different key = cache miss

	if callCount != 2 {
		t.Errorf("expected 2 OPA calls (2 cache misses), got %d", callCount)
	}
}

func TestEval_OPADeniesViaCache(t *testing.T) {
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result":{"allowed":false,"reason":"OPA denied"}}`))
	}))
	defer opaSrv.Close()

	eval := newEval(withOPA(opaSrv.URL), withCacheTTL(time.Minute))
	result, err := eval.Evaluate(qi(paths("block-me")))
	assertBlocked(t, result, err, "OPA denied")

	// Cached deny should persist
	result2, err2 := eval.Evaluate(qi(paths("block-me")))
	assertBlocked(t, result2, err2, "OPA denied")
}

func TestEval_NilLocalCfg(t *testing.T) {
	eval := newEval(withLocal(nil))
	result, err := eval.Evaluate(qi())
	assertAllowed(t, result, err)
}

func TestEval_NilTenants(t *testing.T) {
	eval := newEval(func(e *compositeEvaluator) { e.tenants = nil })
	result, err := eval.Evaluate(qi())
	assertAllowed(t, result, err)
}

// =========================================================================
// Test helpers — DRY
// =========================================================================

func okHandler(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

func failHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not have been called")
	}
}

func serveGET(h http.HandlerFunc, opts ...func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/", nil)
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func withHeader(k, v string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set(k, v) }
}

func assertStatus(t *testing.T, w *httptest.ResponseRecorder, expected int) {
	t.Helper()
	if w.Code != expected {
		t.Errorf("expected status %d, got %d", expected, w.Code)
	}
}

func assertAllowed(t *testing.T, result *rules.Result, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed, got blocked: %s", result.Reason)
	}
}

func assertBlocked(t *testing.T, result *rules.Result, err error, reasonSubstr string) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Errorf("expected blocked, got allowed")
	}
	if reasonSubstr != "" && !contains(result.Reason, reasonSubstr) {
		t.Errorf("expected reason to contain %q, got %q", reasonSubstr, result.Reason)
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
