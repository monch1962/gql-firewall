// Package integration tests the full gql-firewall pipeline end-to-end.
package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/monch1962/gql-firewall/internal/opa"
	"github.com/monch1962/gql-firewall/internal/parser"
	"github.com/monch1962/gql-firewall/internal/proxy"
)

// stubEval wraps an opa.Result to implement proxy.Evaluator.
type stubEval struct {
	result *opa.Result
}

func (e *stubEval) Evaluate(info *parser.QueryInfo) (*opa.Result, error) {
	return e.result, nil
}

func TestIntegration_ValidQueryPasses(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"hello":"world"}}`))
	}))
	defer up.Close()

	h := proxy.MustNew(up.URL, &stubEval{result: &opa.Result{Allowed: true}})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/graphql", "application/json",
		bytes.NewReader(mustJSON(map[string]string{"query": "{ hello }"})))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestIntegration_BlockedQueryReturns403(t *testing.T) {
	h := proxy.MustNew("http://localhost:19999", &stubEval{result: &opa.Result{Allowed: false, Reason: "blocked by policy"}})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/graphql", "application/json",
		bytes.NewReader(mustJSON(map[string]string{"query": "{ secret }"})))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

func TestIntegration_NonGraphQLPathPassesThrough(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer up.Close()

	h := proxy.MustNew(up.URL, &stubEval{result: &opa.Result{Allowed: true}})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestIntegration_DepthBlockedByOPA(t *testing.T) {
	store := opa.NewDataStore()
	store.SetParams(map[string]interface{}{"depth_limit": 3.0})
	eval, err := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package graphql
default allow := false
allow if { count(deny) == 0 }
deny contains msg if {
	input.depth > input.params.depth_limit
	msg := sprintf("depth %d exceeds limit", [input.depth])
}
`,
		Store: store,
	})
	if err != nil {
		t.Fatalf("failed to create embedded evaluator: %v", err)
	}

	// Use a real upstream that we expect NOT to reach
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach upstream for blocked query")
	}))
	defer up.Close()

	h := proxy.MustNew(up.URL, &evalWrapper{eval: eval, store: store})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/graphql", "application/json",
		bytes.NewReader(mustJSON(map[string]string{"query": "{ a { b { c { d } } } }"})))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for deep query, got %d", resp.StatusCode)
	}
}

type evalWrapper struct {
	eval  opa.Evaluator
	store *opa.DataStore
}

func (w *evalWrapper) Evaluate(info *parser.QueryInfo) (*opa.Result, error) {
	input := opa.BuildInput(info, w.store)
	return w.eval.Evaluate(input)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
