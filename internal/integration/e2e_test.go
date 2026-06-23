// Package integration tests the full gql-firewall pipeline end-to-end
// through real HTTP requests against the proxy handler.
package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/monch1962/gql-firewall/internal/opa"
	"github.com/monch1962/gql-firewall/internal/parser"
	"github.com/monch1962/gql-firewall/internal/proxy"
)

// ── helpers ────────────────────────────────────────────────────────────────

// loadPolicy loads the production OPA policy file.
func loadPolicy(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../opa-policies/graphql.rego")
	if err != nil {
		t.Fatalf("loading policy: %v", err)
	}
	return string(data)
}

// newEmbeddedEval creates an embedded OPA evaluator with the production policy
// and the given parameters.
func newEmbeddedEval(t *testing.T, params map[string]interface{}) *opa.EmbeddedEvaluator {
	t.Helper()
	store := opa.NewDataStore()
	store.SetParams(params)
	eval, err := opa.NewEmbedded(opa.EmbedConfig{
		Policy: loadPolicy(t),
		Store:  store,
	})
	if err != nil {
		t.Fatalf("creating embedded evaluator: %v", err)
	}
	return eval
}

// downstreamProxiedEval wraps an opa.Evaluator to implement proxy.Evaluator
// by building the input from parser.QueryInfo.
type downstreamProxiedEval struct {
	eval  opa.Evaluator
	store *opa.DataStore
}

func (d *downstreamProxiedEval) Evaluate(info *parser.QueryInfo) (*opa.Result, error) {
	input := opa.BuildInput(info, d.store)
	return d.eval.Evaluate(input)
}

// testUpstream creates an HTTP test server that acts as the GraphQL upstream.
func testUpstream(t *testing.T, handler func(http.ResponseWriter, *http.Request)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(handler))
}

// postGraphQL sends a POST /graphql with the given query and optional headers.
func postGraphQL(t *testing.T, baseURL, query string, headers ...string) *http.Response {
	t.Helper()
	body := map[string]string{"query": query}
	data, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", baseURL+"/graphql", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return resp
}

// readBody reads the full response body and closes it.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return string(data)
}

// ── Proxy infrastructure tests ─────────────────────────────────────────────

func TestE2E_ValidQuery_200WithUpstreamResponse(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !bytes.Contains(body, []byte("hello")) {
			t.Error("upstream did not receive original query body")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"hello":"world"}}`))
	})
	defer up.Close()

	store := opa.NewDataStore()
	store.SetParams(map[string]interface{}{"depth_limit": 10.0, "max_field_count": 100.0})
	eval := newEmbeddedEval(t, store.GetParams())
	proxyHandler := proxy.MustNew(up.URL, &downstreamProxiedEval{eval: eval, store: store})
	srv := httptest.NewServer(proxyHandler)
	defer srv.Close()

	resp := postGraphQL(t, srv.URL, "{ hello }")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "world") {
		t.Errorf("expected upstream response body, got %s", body)
	}
}

func TestE2E_BlockedQuery_403WithValidJSON(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be reached for blocked query")
	})
	defer up.Close()

	store := opa.NewDataStore()
	store.SetParams(map[string]interface{}{"depth_limit": 5.0, "max_field_count": 100.0})
	eval := newEmbeddedEval(t, store.GetParams())
	proxyHandler := proxy.MustNew(up.URL, &downstreamProxiedEval{eval: eval, store: store})
	srv := httptest.NewServer(proxyHandler)
	defer srv.Close()

	resp := postGraphQL(t, srv.URL, "{ a { b { c { d { e { f } } } } } }")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", resp.StatusCode, body)
	}
	// Response must be valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("blocked response is not valid JSON: %s (err: %v)", body, err)
	}
	if parsed["error"] == nil || parsed["reason"] == nil {
		t.Errorf("expected 'error' and 'reason' fields in blocked response, got %v", parsed)
	}
}

func TestE2E_NonGraphQLPath_PassesThrough(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"alive"}`))
	})
	defer up.Close()

	store := opa.NewDataStore()
	store.SetParams(map[string]interface{}{"depth_limit": 10.0})
	eval := newEmbeddedEval(t, store.GetParams())
	proxyHandler := proxy.MustNew(up.URL, &downstreamProxiedEval{eval: eval, store: store})
	srv := httptest.NewServer(proxyHandler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "alive") {
		t.Errorf("expected upstream response, got %s", body)
	}
}

func TestE2E_MissingContentType_415(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be reached")
	})
	defer up.Close()

	store := opa.NewDataStore()
	store.SetParams(map[string]interface{}{})
	eval := newEmbeddedEval(t, store.GetParams())
	proxyHandler := proxy.MustNew(up.URL, &downstreamProxiedEval{eval: eval, store: store})
	srv := httptest.NewServer(proxyHandler)
	defer srv.Close()

	data, _ := json.Marshal(map[string]string{"query": "{ hello }"})
	req, _ := http.NewRequest("POST", srv.URL+"/graphql", bytes.NewReader(data))
	// No Content-Type header
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d: %s", resp.StatusCode, body)
	}
}

func TestE2E_InvalidJSONBody_400(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be reached")
	})
	defer up.Close()

	store := opa.NewDataStore()
	store.SetParams(map[string]interface{}{})
	eval := newEmbeddedEval(t, store.GetParams())
	proxyHandler := proxy.MustNew(up.URL, &downstreamProxiedEval{eval: eval, store: store})
	srv := httptest.NewServer(proxyHandler)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/graphql", "application/json",
		bytes.NewReader([]byte(`not-json-at-all`)))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", resp.StatusCode, body)
	}
}

func TestE2E_EmptyQueryField_400(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be reached")
	})
	defer up.Close()

	store := opa.NewDataStore()
	store.SetParams(map[string]interface{}{})
	eval := newEmbeddedEval(t, store.GetParams())
	proxyHandler := proxy.MustNew(up.URL, &downstreamProxiedEval{eval: eval, store: store})
	srv := httptest.NewServer(proxyHandler)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/graphql", "application/json",
		bytes.NewReader([]byte(`{"query":""}`)))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", resp.StatusCode, body)
	}
}

func TestE2E_HeadersForwardedToUpstream(t *testing.T) {
	var gotAuth, gotCustom string
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCustom = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})
	defer up.Close()

	store := opa.NewDataStore()
	store.SetParams(map[string]interface{}{"depth_limit": 10.0})
	eval := newEmbeddedEval(t, store.GetParams())
	proxyHandler := proxy.MustNew(up.URL, &downstreamProxiedEval{eval: eval, store: store})
	srv := httptest.NewServer(proxyHandler)
	defer srv.Close()

	resp := postGraphQL(t, srv.URL, "{ hello }",
		"Authorization", "Bearer token123",
		"X-Custom", "custom-value",
	)
	readBody(t, resp)

	if gotAuth != "Bearer token123" {
		t.Errorf("expected Authorization header forwarded, got %q", gotAuth)
	}
	if gotCustom != "custom-value" {
		t.Errorf("expected X-Custom header forwarded, got %q", gotCustom)
	}
}

func TestE2E_UpstreamError_Forwarded(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	})
	defer up.Close()

	store := opa.NewDataStore()
	store.SetParams(map[string]interface{}{"depth_limit": 10.0})
	eval := newEmbeddedEval(t, store.GetParams())
	proxyHandler := proxy.MustNew(up.URL, &downstreamProxiedEval{eval: eval, store: store})
	srv := httptest.NewServer(proxyHandler)
	defer srv.Close()

	resp := postGraphQL(t, srv.URL, "{ hello }")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "internal error") {
		t.Errorf("expected upstream error body, got %s", body)
	}
}

func TestE2E_BlockedResponse_ValidJSON(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach upstream")
	})
	defer up.Close()

	store := opa.NewDataStore()
	store.SetParams(map[string]interface{}{
		"depth_limit":     3.0,
		"max_field_count": 100.0,
		"cost_budget":     200.0,
		"field_blocklist": []interface{}{"user.ssn"},
	})
	eval := newEmbeddedEval(t, store.GetParams())
	proxyHandler := proxy.MustNew(up.URL, &downstreamProxiedEval{eval: eval, store: store})
	srv := httptest.NewServer(proxyHandler)
	defer srv.Close()

	reasons := []string{"a { b { c { d } } }", "user { ssn }"}
	for _, q := range reasons {
		resp := postGraphQL(t, srv.URL, "{ "+q+" }")
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403 for query %q, got %d: %s", q, resp.StatusCode, body)
		}
		if !json.Valid([]byte(body)) {
			t.Errorf("blocked response not valid JSON for query %q: %s", q, body)
		}
	}
}

// ── OWASP attack categories through full pipeline ──────────────────────────

func TestE2E_DepthDoS_Blocked(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach upstream")
	})
	defer up.Close()

	store := opa.NewDataStore()
	store.SetParams(map[string]interface{}{"depth_limit": 5.0, "max_field_count": 100.0, "cost_budget": 100.0})
	eval := newEmbeddedEval(t, store.GetParams())
	proxyHandler := proxy.MustNew(up.URL, &downstreamProxiedEval{eval: eval, store: store})
	srv := httptest.NewServer(proxyHandler)
	defer srv.Close()

	resp := postGraphQL(t, srv.URL, "{ a { b { c { d { e { f } } } } } }")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for deep query, got %d: %s", resp.StatusCode, body)
	}
}

func TestE2E_AliasDoS_Blocked(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach upstream")
	})
	defer up.Close()

	store := opa.NewDataStore()
	store.SetParams(map[string]interface{}{
		"depth_limit": 10.0, "max_field_count": 10.0, "cost_budget": 500.0,
	})
	eval := newEmbeddedEval(t, store.GetParams())
	proxyHandler := proxy.MustNew(up.URL, &downstreamProxiedEval{eval: eval, store: store})
	srv := httptest.NewServer(proxyHandler)
	defer srv.Close()

	resp := postGraphQL(t, srv.URL, "{ a b c d e f g h i j k l m n o }")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for high field count, got %d: %s", resp.StatusCode, body)
	}
}

func TestE2E_FieldBlocklist_Blocked(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach upstream")
	})
	defer up.Close()

	store := opa.NewDataStore()
	store.SetParams(map[string]interface{}{
		"depth_limit":      10.0,
		"max_field_count":  100.0,
		"field_blocklist":  []interface{}{"user.ssn"},
	})
	eval := newEmbeddedEval(t, store.GetParams())
	proxyHandler := proxy.MustNew(up.URL, &downstreamProxiedEval{eval: eval, store: store})
	srv := httptest.NewServer(proxyHandler)
	defer srv.Close()

	resp := postGraphQL(t, srv.URL, "{ user { ssn } }")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for blocked field, got %d: %s", resp.StatusCode, body)
	}
}

func TestE2E_FieldAllowlist_BlocksNonListed(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach upstream")
	})
	defer up.Close()

	store := opa.NewDataStore()
	store.SetParams(map[string]interface{}{
		"depth_limit":      10.0,
		"max_field_count":  100.0,
		"field_allowlist":  []interface{}{"user.name"},
	})
	eval := newEmbeddedEval(t, store.GetParams())
	proxyHandler := proxy.MustNew(up.URL, &downstreamProxiedEval{eval: eval, store: store})
	srv := httptest.NewServer(proxyHandler)
	defer srv.Close()

	resp := postGraphQL(t, srv.URL, "{ user { ssn } }")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for non-allowlisted field, got %d: %s", resp.StatusCode, body)
	}
}

func TestE2E_OperationType_BlockedSubscription(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach upstream")
	})
	defer up.Close()

	store := opa.NewDataStore()
	store.SetParams(map[string]interface{}{
		"depth_limit":         10.0,
		"max_field_count":     100.0,
		"blocked_operations":  []interface{}{"subscription"},
	})
	eval := newEmbeddedEval(t, store.GetParams())
	proxyHandler := proxy.MustNew(up.URL, &downstreamProxiedEval{eval: eval, store: store})
	srv := httptest.NewServer(proxyHandler)
	defer srv.Close()

	resp := postGraphQL(t, srv.URL, "subscription OnMsg { messageAdded { id } }")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for blocked subscription, got %d: %s", resp.StatusCode, body)
	}
}

func TestE2E_ShallowQuery_PassesToUpstream(t *testing.T) {
	upReached := false
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upReached = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"ok":true}}`))
	})
	defer up.Close()

	store := opa.NewDataStore()
	store.SetParams(map[string]interface{}{"depth_limit": 10.0, "max_field_count": 100.0})
	eval := newEmbeddedEval(t, store.GetParams())
	proxyHandler := proxy.MustNew(up.URL, &downstreamProxiedEval{eval: eval, store: store})
	srv := httptest.NewServer(proxyHandler)
	defer srv.Close()

	resp := postGraphQL(t, srv.URL, "{ hello }")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	if !upReached {
		t.Error("upstream was not reached for valid query")
	}
}

func TestE2E_MultipleAttackVectors_PipelineHolds(t *testing.T) {
	// Use a permissive policy and verify each attack type independently
	tests := []struct {
		name  string
		query string
		params map[string]interface{}
		want  int
	}{
		{
			name:  "deep query blocked",
			query: "{ a { b { c { d { e } } } } }",
			params: map[string]interface{}{"depth_limit": 3.0, "max_field_count": 100.0, "cost_budget": 200.0},
			want:  http.StatusForbidden,
		},
		{
			name:  "shallow query allowed",
			query: "{ hello }",
			params: map[string]interface{}{"depth_limit": 10.0, "max_field_count": 100.0},
			want:  http.StatusOK,
		},
		{
			name:  "blocked field denied",
			query: "{ admin { secretKey } }",
			params: map[string]interface{}{"depth_limit": 10.0, "max_field_count": 100.0,
				"field_blocklist": []interface{}{"admin.secretKey"}},
			want: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"data":{"ok":true}}`))
			})
			defer up.Close()

			store := opa.NewDataStore()
			store.SetParams(tt.params)
			eval := newEmbeddedEval(t, store.GetParams())
			proxyHandler := proxy.MustNew(up.URL, &downstreamProxiedEval{eval: eval, store: store})
			srv := httptest.NewServer(proxyHandler)
			defer srv.Close()

			resp := postGraphQL(t, srv.URL, tt.query)
			body := readBody(t, resp)

			if resp.StatusCode != tt.want {
				t.Errorf("expected status %d, got %d: %s", tt.want, resp.StatusCode, body)
			}
		})
	}
}
