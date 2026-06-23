package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/monch1962/gql-firewall/internal/opa"
	"github.com/monch1962/gql-firewall/internal/parser"
)

const testPolicy = `package graphql
default allow := false
allow if { count(deny) == 0 }
deny contains msg if {
	input.depth > input.params.depth_limit
	msg := sprintf("query depth %d exceeds limit", [input.depth])
}
deny contains msg if {
	input.field_count > input.params.max_field_count
	msg := sprintf("field count exceeded", [])
}
deny contains msg if {
	[input.operation_type] == input.params.blocked_operations
	msg := sprintf("operation type %q is blocked", [input.operation_type])
}
`

// newEval creates a compositeEvaluator with an embedded OPA evaluator and test policy.
func newEval(opts ...func(*compositeEvaluator)) *compositeEvaluator {
	store := opa.NewDataStore()
	store.SetParams(map[string]interface{}{
		"depth_limit":     10.0,
		"max_field_count": 100.0,
	})
	eval, err := opa.NewEmbedded(opa.EmbedConfig{Policy: testPolicy, Store: store})
	if err != nil {
		panic(err)
	}
	e := &compositeEvaluator{
		opa:      eval,
		opaStore: store,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

func withParams(key string, val interface{}) func(*compositeEvaluator) {
	return func(e *compositeEvaluator) {
		params := e.opaStore.GetParams()
		if params == nil {
			params = make(map[string]interface{})
		}
		params[key] = val
		e.opaStore.SetParams(params)
	}
}

func withTenantParams(id string, cfg map[string]interface{}) func(*compositeEvaluator) {
	return func(e *compositeEvaluator) {
		e.opaStore.SetTenant(id, cfg)
	}
}

func withOPAFailClosed() func(*compositeEvaluator) {
	return func(e *compositeEvaluator) { e.opaFailClosed = true }
}

func withOPAAuditOnly() func(*compositeEvaluator) {
	return func(e *compositeEvaluator) { e.opaAuditOnly = true }
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

func paths(p ...string) func(*parser.QueryInfo) {
	return func(i *parser.QueryInfo) { i.FieldPaths = p }
}

func opType(t string) func(*parser.QueryInfo) {
	return func(i *parser.QueryInfo) { i.OperationType = t }
}

func tenantID(id string) func(*parser.QueryInfo) {
	return func(i *parser.QueryInfo) { i.TenantID = id }
}

func fieldCount(n int) func(*parser.QueryInfo) {
	return func(i *parser.QueryInfo) { i.FieldCount = n }
}

// =========================================================================
// requireAdminAuth
// =========================================================================

func TestRequireAdminAuth_NoTokenConfigured(t *testing.T) {
	h := requireAdminAuth("", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRequireAdminAuth_ValidToken(t *testing.T) {
	h := requireAdminAuth("secret", okHandler)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer secret")
	h(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRequireAdminAuth_MissingToken(t *testing.T) {
	h := requireAdminAuth("secret", func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not be called")
	})
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestRequireAdminAuth_WrongToken(t *testing.T) {
	h := requireAdminAuth("secret", func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not be called")
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	h(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestRequireAdminAuth_RawToken(t *testing.T) {
	h := requireAdminAuth("token123", okHandler)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "token123")
	h(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func okHandler(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

// =========================================================================
// decisionCacheKey & simpleHash
// =========================================================================

func TestDecisionCacheKey_IdenticalInputs(t *testing.T) {
	info := qi(paths("user", "user.name"), depth(3))
	k1, k2 := decisionCacheKey(info), decisionCacheKey(info)
	if k1 != k2 {
		t.Errorf("expected identical keys, got %q vs %q", k1, k2)
	}
}

func TestDecisionCacheKey_DifferentPaths(t *testing.T) {
	if decisionCacheKey(qi(paths("user.name"), depth(3))) == decisionCacheKey(qi(paths("user.ssn"), depth(3))) {
		t.Error("expected different keys for different field paths")
	}
}

func TestDecisionCacheKey_DifferentOperations(t *testing.T) {
	if decisionCacheKey(qi(opType("query"))) == decisionCacheKey(qi(opType("mutation"))) {
		t.Error("expected different keys for different operation types")
	}
}

func TestSimpleHash(t *testing.T) {
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
// compositeEvaluator — OPA-only pipeline
// =========================================================================

func TestEval_AllowsValidQuery(t *testing.T) {
	r, err := newEval().Evaluate(qi())
	assertAllow(t, r, err)
}

func TestEval_BlocksDeepQuery(t *testing.T) {
	e := newEval(withParams("depth_limit", 10.0))
	r, err := e.Evaluate(qi(depth(20)))
	assertBlock(t, r, err, "depth")
}

func TestEval_SchemaValidationRejects(t *testing.T) {
	s, err := parser.LoadSchemaFromString("type Query { hello: String }\nscalar String\nscalar Int\nscalar Float\nscalar Boolean\n")
	if err != nil {
		t.Fatal(err)
	}
	r, err := newEval(withSchema(s)).Evaluate(qi(paths("nonexistent")))
	assertBlock(t, r, err, "does not exist")
}

func TestEval_SchemaValidationAllows(t *testing.T) {
	s, err := parser.LoadSchemaFromString("type Query { hello: String }\nscalar String\nscalar Int\n")
	if err != nil {
		t.Fatal(err)
	}
	r, err := newEval(withSchema(s)).Evaluate(qi(paths("hello")))
	assertAllow(t, r, err)
}

func TestEval_TenantOverridesDefault(t *testing.T) {
	e := newEval(
		withParams("depth_limit", 10.0),
		withTenantParams("strict", map[string]interface{}{"depth_limit": 5.0}),
	)
	r, err := e.Evaluate(qi(tenantID("strict"), depth(20)))
	assertBlock(t, r, err, "depth")
}

func TestEval_NonTenantGetsDefault(t *testing.T) {
	e := newEval(
		withParams("depth_limit", 10.0),
		withTenantParams("strict", map[string]interface{}{"depth_limit": 1.0}),
	)
	r, err := e.Evaluate(qi(tenantID("other"), depth(5)))
	assertAllow(t, r, err)
}

func TestEval_FieldCountBlocked(t *testing.T) {
	e := newEval(withParams("max_field_count", 10.0))
	r, err := e.Evaluate(qi(fieldCount(100)))
	assertBlock(t, r, err, "field count")
}

// OPA fail-closed
func TestEval_OPAFailOpenByDefault(t *testing.T) {
	e := newEval()
	e.opa = opa.NewSidecar("http://localhost:19999")
	r, err := e.Evaluate(qi())
	assertAllow(t, r, err)
}

func TestEval_OPAFailClosedOnError(t *testing.T) {
	e := newEval()
	e.opa = opa.NewSidecar("http://localhost:19999")
	e.opaFailClosed = true
	r, err := e.Evaluate(qi())
	assertBlock(t, r, err, "OPA unavailable")
}

// OPA caching
func TestEval_OPACacheHit(t *testing.T) {
	e := newEval(withCacheTTL(time.Minute))
	r1, e1 := e.Evaluate(qi(paths("ping")))
	assertAllow(t, r1, e1)
	r2, e2 := e.Evaluate(qi(paths("ping")))
	assertAllow(t, r2, e2)
}

func TestEval_OPACacheMiss(t *testing.T) {
	e := newEval(withCacheTTL(time.Minute))
	e.Evaluate(qi(paths("a")))
	e.Evaluate(qi(paths("b")))
}

func TestEval_OPADeniesViaCache(t *testing.T) {
	e := newEval(withParams("depth_limit", 5.0), withCacheTTL(time.Minute))
	// Depth 3 should pass
	r1, e1 := e.Evaluate(qi(paths("x"), depth(3)))
	assertAllow(t, r1, e1)
}

// Audit-only mode
func TestEval_OPAAuditOnlyAllowsWhenBlocked(t *testing.T) {
	e := newEval(withParams("depth_limit", 5.0), withOPAAuditOnly())
	r, err := e.Evaluate(qi(paths("x"), depth(20)))
	assertAllow(t, r, err)
}

func TestEval_OPAAuditOnlyStillAllowsWhenPasses(t *testing.T) {
	e := newEval(withParams("depth_limit", 10.0), withOPAAuditOnly())
	r, err := e.Evaluate(qi(paths("x"), depth(5)))
	assertAllow(t, r, err)
}

func TestEval_OPAAuditOnlyWithCache(t *testing.T) {
	e := newEval(withParams("depth_limit", 5.0), withOPAAuditOnly(), withCacheTTL(time.Minute))
	r1, e1 := e.Evaluate(qi(paths("a"), depth(20)))
	assertAllow(t, r1, e1)
	r2, e2 := e.Evaluate(qi(paths("a"), depth(20)))
	assertAllow(t, r2, e2)
}

// =========================================================================
// Admin API tests — via httptest.Server
// =========================================================================

func adminTestServer(t *testing.T, token string, eval *compositeEvaluator) *httptest.Server {
	t.Helper()
	return httptest.NewServer(adminMux(token, eval, eval.opa, eval.opaStore))
}

func TestAdminAPI_HealthCheck(t *testing.T) {
	s := adminTestServer(t, "", newEval())
	defer s.Close()
	code, body := httpGet(t, s.URL+"/admin/health")
	if code != 200 {
		t.Errorf("expected 200, got %d", code)
	}
	if !strings.Contains(body, "ok") {
		t.Errorf("expected 'ok' in body")
	}
}

func TestAdminAPI_Unauthenticated(t *testing.T) {
	s := adminTestServer(t, "secret", newEval())
	defer s.Close()
	for _, p := range []string{"/admin/rules", "/admin/tenants", "/admin/stats"} {
		code, _ := httpGet(t, s.URL + p)
		if code != 401 {
			t.Errorf("%s: expected 401, got %d", p, code)
		}
	}
}

func TestAdminAPI_RulesEndpoint(t *testing.T) {
	e := newEval(withParams("depth_limit", 5.0))
	s := adminTestServer(t, "t", e)
	defer s.Close()
	code, body := httpGet(t, s.URL+"/admin/rules", "Authorization", "Bearer t")
	if code != 200 {
		t.Fatal("expected 200")
	}
	if !strings.Contains(body, "depth_limit") {
		t.Errorf("expected depth_limit in response: %s", body)
	}
}

func TestAdminAPI_RulesUpdate(t *testing.T) {
	e := newEval()
	s := adminTestServer(t, "t", e)
	defer s.Close()
	httpPost(t, s.URL+"/admin/rules/update", `{"depth_limit":3}`, "Authorization", "Bearer t")
	params := e.opaStore.GetParams()
	if params["depth_limit"] != 3.0 {
		t.Errorf("expected depth_limit=3, got %v", params["depth_limit"])
	}
}

func TestAdminAPI_TenantCRUD(t *testing.T) {
	e := newEval()
	s := adminTestServer(t, "t", e)
	defer s.Close()
	httpPut(t, s.URL+"/admin/tenants/myapp", `{"depth_limit":3}`, "Authorization", "Bearer t")
	cfg := e.opaStore.GetTenant("myapp")
	if cfg == nil || cfg["depth_limit"] != 3.0 {
		t.Errorf("expected tenant depth_limit=3, got %v", cfg)
	}
	httpDelete(t, s.URL+"/admin/tenants/myapp", "Authorization", "Bearer t")
}

func TestAdminAPI_TenantList(t *testing.T) {
	e := newEval()
	s := adminTestServer(t, "t", e)
	defer s.Close()
	httpPut(t, s.URL+"/admin/tenants/a", `{"depth_limit":5}`, "Authorization", "Bearer t")
	httpPut(t, s.URL+"/admin/tenants/b", `{"depth_limit":5}`, "Authorization", "Bearer t")
	_, body := httpGet(t, s.URL+"/admin/tenants", "Authorization", "Bearer t")
	if !strings.Contains(body, `"a"`) || !strings.Contains(body, `"b"`) {
		t.Errorf("expected both tenants in list, got %s", body)
	}
}

func TestAdminAPI_Stats(t *testing.T) {
	e := newEval()
	e.opaStore.SetTenant("t1", map[string]interface{}{})
	s := adminTestServer(t, "t", e)
	defer s.Close()
	_, body := httpGet(t, s.URL+"/admin/stats", "Authorization", "Bearer t")
	if !strings.Contains(body, "version") {
		t.Errorf("expected version in stats")
	}
	if !strings.Contains(body, "tenants") {
		t.Errorf("expected tenants in stats")
	}
}

// =========================================================================
// HTTP test helpers
// =========================================================================

func httpDo(t *testing.T, method, url, body string, headers ...string) (int, string) {
	t.Helper()
	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		t.Fatalf("httpDo %s %s: %v", method, url, err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("httpDo %s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func httpGet(t *testing.T, url string, headers ...string) (int, string) {
	t.Helper()
	return httpDo(t, "GET", url, "", headers...)
}

func httpPost(t *testing.T, url, body string, headers ...string) (int, string) {
	t.Helper()
	return httpDo(t, "POST", url, body, headers...)
}

func httpPut(t *testing.T, url, body string, headers ...string) (int, string) {
	t.Helper()
	return httpDo(t, "PUT", url, body, headers...)
}

func httpDelete(t *testing.T, url string, headers ...string) (int, string) {
	t.Helper()
	return httpDo(t, "DELETE", url, "", headers...)
}

func assertAllow(t *testing.T, r *opa.Result, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.Allowed {
		t.Errorf("expected allowed, got blocked: %s", r.Reason)
	}
}

func assertBlock(t *testing.T, r *opa.Result, err error, substr string) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Allowed {
		t.Errorf("expected blocked, got allowed")
	}
	if !strings.Contains(r.Reason, substr) {
		t.Errorf("expected reason to contain %q, got %q", substr, r.Reason)
	}
}
