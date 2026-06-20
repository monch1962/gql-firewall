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
	"github.com/monch1962/gql-firewall/internal/rules"
	"github.com/monch1962/gql-firewall/internal/tenant"
)

// newEval is a DRY helper that creates a compositeEvaluator with sensible defaults.
func newEval(opts ...func(*compositeEvaluator)) *compositeEvaluator {
	e := &compositeEvaluator{
		local:    &rules.Config{DepthLimit: 10},
		opa:      opa.New(""),
		tenants:  tenant.New(&rules.Config{}),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

func withLocal(cfg *rules.Config) func(*compositeEvaluator) {
	return func(e *compositeEvaluator) { e.local = cfg }
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
// compositeEvaluator — full path coverage
// =========================================================================

func TestEval_AllowsValidQuery(t *testing.T) {
	r, err := newEval().Evaluate(qi())
	assertAllow(t, r, err)
}

func TestEval_BlocksDeepQuery(t *testing.T) {
	r, err := newEval().Evaluate(qi(depth(20)))
	assertBlock(t, r, err, "depth")
}

func TestEval_BlocksBlockedField(t *testing.T) {
	e := newEval(withLocal(&rules.Config{FieldBlocklist: []string{"user.ssn"}}))
	r, err := e.Evaluate(qi(paths("user", "user.ssn")))
	assertBlock(t, r, err, "ssn")
}

func TestEval_BlocksDisallowedOperation(t *testing.T) {
	e := newEval(withLocal(&rules.Config{AllowedOperations: []string{"query"}}))
	r, err := e.Evaluate(qi(opType("mutation")))
	assertBlock(t, r, err, "mutation")
}

func TestEval_TenantOverridesDefault(t *testing.T) {
	e := newEval(withTenantOverride("strict", &rules.Config{DepthLimit: 5}))
	r, err := e.Evaluate(qi(tenantID("strict"), depth(20)))
	assertBlock(t, r, err, "depth")
}

func TestEval_NonTenantGetsDefault(t *testing.T) {
	e := newEval(withLocal(&rules.Config{}), withTenantOverride("strict", &rules.Config{DepthLimit: 1}))
	r, err := e.Evaluate(qi(tenantID("other"), depth(20)))
	assertAllow(t, r, err)
}

func TestEval_TenantAllowsWhenPermits(t *testing.T) {
	e := newEval(withLocal(&rules.Config{}), withTenantOverride("relaxed", &rules.Config{DepthLimit: 50}))
	r, err := e.Evaluate(qi(tenantID("relaxed"), depth(20)))
	assertAllow(t, r, err)
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

func TestEval_OPAFailOpenOnError(t *testing.T) {
	e := newEval(withOPA("http://localhost:19999"))
	r, err := e.Evaluate(qi())
	assertAllow(t, r, err)
}

func TestEval_OPAFailClosedOnError(t *testing.T) {
	e := newEval(withOPA("http://localhost:19999"), withOPAFailClosed())
	r, err := e.Evaluate(qi())
	assertBlock(t, r, err, "OPA unavailable")
}

func TestEval_OPACacheHit(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result":{"allowed":true}}`))
	}))
	defer s.Close()
	e := newEval(withOPA(s.URL), withCacheTTL(time.Minute))
	r1, e1 := e.Evaluate(qi(paths("ping")))
	assertAllow(t, r1, e1)
	r2, e2 := e.Evaluate(qi(paths("ping"))) // cache hit
	assertAllow(t, r2, e2)
}

func TestEval_OPACacheMiss(t *testing.T) {
	var n int
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n++; w.Write([]byte(`{"result":{"allowed":true}}`)) }))
	defer s.Close()
	e := newEval(withOPA(s.URL), withCacheTTL(time.Minute))
	e.Evaluate(qi(paths("a")))
	e.Evaluate(qi(paths("b")))
	if n != 2 {
		t.Errorf("expected 2 OPA calls (2 cache misses), got %d", n)
	}
}

func TestEval_OPADeniesViaCache(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result":{"allowed":false,"reason":"OPA denied"}}`))
	}))
	defer s.Close()
	e := newEval(withOPA(s.URL), withCacheTTL(time.Minute))
	r1, e1 := e.Evaluate(qi(paths("x")))
	assertBlock(t, r1, e1, "OPA denied")
	r2, e2 := e.Evaluate(qi(paths("x"))) // cached
	assertBlock(t, r2, e2, "OPA denied")
}

func TestEval_NilLocalCfg(t *testing.T) {
	r, err := newEval(withLocal(nil)).Evaluate(qi())
	assertAllow(t, r, err)
}

func TestEval_NilTenants(t *testing.T) {
	e := newEval(func(ev *compositeEvaluator) { ev.tenants = tenant.New(&rules.Config{}) })
	r, err := e.Evaluate(qi())
	assertAllow(t, r, err)
}

// =========================================================================
// Admin API tests — via httptest.Server
// =========================================================================

func adminTestServer(t *testing.T, token string, eval *compositeEvaluator) *httptest.Server {
	t.Helper()
	return httptest.NewServer(adminMux(token, eval))
}

func TestAdminAPI_HealthCheck(t *testing.T) {
	s := adminTestServer(t, "", newEval())
	defer s.Close()
	code, body := httpGet(t, s.URL + "/admin/health")
	if code != 200 { t.Errorf("expected 200, got %d", code) }
	if !strings.Contains(body, "ok") { t.Errorf("expected 'ok' in body") }
}

func TestAdminAPI_Unauthenticated(t *testing.T) {
	s := adminTestServer(t, "secret", newEval())
	defer s.Close()
	for _, p := range []string{"/admin/rules", "/admin/tenants", "/admin/stats"} {
		code, _ := httpGet(t, s.URL+p)
		if code != 401 { t.Errorf("%s: expected 401, got %d", p, code) }
	}
}

func TestAdminAPI_RulesEndpoint(t *testing.T) {
	e := newEval(withLocal(&rules.Config{DepthLimit: 5}))
	s := adminTestServer(t, "t", e)
	defer s.Close()
	code, body := httpGet(t, s.URL+"/admin/rules", "Authorization", "Bearer t")
	if code != 200 { t.Fatal("expected 200") }
	if !strings.Contains(body, `"depth_limit":5`) { t.Errorf("expected depth_limit:5") }
}

func TestAdminAPI_RulesUpdate(t *testing.T) {
	e := newEval()
	s := adminTestServer(t, "t", e)
	defer s.Close()
	httpPost(t, s.URL+"/admin/rules/update", `{"depth_limit":3}`, "Authorization", "Bearer t")
	e.mu.RLock()
	if e.local.DepthLimit != 3 { t.Errorf("expected DepthLimit=3, got %d", e.local.DepthLimit) }
	e.mu.RUnlock()
}

func TestAdminAPI_RejectsEmptyConfig(t *testing.T) {
	s := adminTestServer(t, "t", newEval())
	defer s.Close()
	code, body := httpPost(t, s.URL+"/admin/rules/update", `{}`, "Authorization", "Bearer t")
	if code != 400 { t.Errorf("expected 400, got %d", code) }
	if !strings.Contains(body, "invalid config") { t.Errorf("expected 'invalid config' in body") }
}

func TestAdminAPI_TenantCRUD(t *testing.T) {
	e := newEval()
	s := adminTestServer(t, "t", e)
	defer s.Close()
	httpPut(t, s.URL+"/admin/tenants/myapp", `{"depth_limit":3}`, "Authorization", "Bearer t")
	if c := e.tenants.Get("myapp"); c == nil || c.DepthLimit != 3 { t.Errorf("expected tenant DepthLimit=3") }
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
	e.tenants.Set("t1", &rules.Config{})
	s := adminTestServer(t, "t", e)
	defer s.Close()
	_, body := httpGet(t, s.URL+"/admin/stats", "Authorization", "Bearer t")
	if !strings.Contains(body, "version") { t.Errorf("expected version in stats") }
	if !strings.Contains(body, "tenants") { t.Errorf("expected tenants in stats") }
}

// =========================================================================
// HTTP test helpers
// =========================================================================

func httpGet(t *testing.T, url string, headers ...string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatalf("httpGet %s: %v", url, err) }
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func httpPost(t *testing.T, url, body string, headers ...string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatalf("httpPost %s: %v", url, err) }
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func httpPut(t *testing.T, url, body string, headers ...string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("PUT", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatalf("httpPut %s: %v", url, err) }
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func httpDelete(t *testing.T, url string, headers ...string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("DELETE", url, nil)
	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatalf("httpDelete %s: %v", url, err) }
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func assertAllow(t *testing.T, r *rules.Result, err error) {
	t.Helper()
	if err != nil { t.Fatalf("unexpected error: %v", err) }
	if !r.Allowed { t.Errorf("expected allowed, got blocked: %s", r.Reason) }
}

func assertBlock(t *testing.T, r *rules.Result, err error, substr string) {
	t.Helper()
	if err != nil { t.Fatalf("unexpected error: %v", err) }
	if r.Allowed { t.Errorf("expected blocked, got allowed") }
	if !strings.Contains(r.Reason, substr) {
		t.Errorf("expected reason to contain %q, got %q", substr, r.Reason)
	}
}
