// Package integration tests the full gql-firewall pipeline end-to-end:
// HTTP request → GraphQL parsing → rule evaluation → forward/block.
package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/monch1962/gql-firewall/internal/config"
	"github.com/monch1962/gql-firewall/internal/opa"
	"github.com/monch1962/gql-firewall/internal/parser"
	"github.com/monch1962/gql-firewall/internal/proxy"
	"github.com/monch1962/gql-firewall/internal/rules"
)

// evalConfig wraps rules.Config to implement proxy.Evaluator.
type evalConfig struct{ *rules.Config }

func (e *evalConfig) Evaluate(info *parser.QueryInfo) (*rules.Result, error) {
	return e.Config.Evaluate(info), nil
}

// evalConfigAndOPA checks local rules first, then OPA.
type evalConfigAndOPA struct {
	local *rules.Config
	opa   *opa.Client
}

func (e *evalConfigAndOPA) Evaluate(info *parser.QueryInfo) (*rules.Result, error) {
	if e.local != nil {
		r := e.local.Evaluate(info)
		if !r.Allowed {
			return r, nil
		}
	}
	if e.opa != nil {
		return e.opa.Evaluate(info)
	}
	return &rules.Result{Allowed: true}, nil
}

func TestFullPipeline_AllowQuery(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		json.Unmarshal(body, &req)
		if req["query"] != "{ hello }" {
			t.Errorf("unexpected query: %v", req["query"])
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data": {"hello": "world"}}`))
	}))
	defer upstream.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "rules.json")
	os.WriteFile(cfgPath, []byte(`{"depth_limit": 5, "max_field_count": 20}`), 0644)
	cfg, _ := config.Load(cfgPath)

	handler, _ := proxy.New(upstream.URL, &evalConfig{cfg})
	req := httptest.NewRequest("POST", "/graphql",
		bytes.NewReader([]byte(`{"query": "{ hello }"}`)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("world")) {
		t.Errorf("expected upstream response, got %s", string(body))
	}
}

func TestFullPipeline_BlockDeepQuery(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called")
	}))
	defer upstream.Close()

	cfg := &rules.Config{DepthLimit: 3}
	handler, _ := proxy.New(upstream.URL, &evalConfig{cfg})

	req := httptest.NewRequest("POST", "/graphql",
		bytes.NewReader([]byte(`{"query": "{ a { b { c { d } } } }"}`)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestFullPipeline_BlockSSNField(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called")
	}))
	defer upstream.Close()

	cfg := &rules.Config{FieldBlocklist: []string{"user.ssn"}}
	handler, _ := proxy.New(upstream.URL, &evalConfig{cfg})

	req := httptest.NewRequest("POST", "/graphql",
		bytes.NewReader([]byte(`{"query": "{ user { name ssn } }"}`)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestFullPipeline_OPAIntegration(t *testing.T) {
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result": {"allowed": true}}`))
	}))
	defer opaSrv.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data": {"ok": true}}`))
	}))
	defer upstream.Close()

	opaClient := opa.New(opaSrv.URL)
	handler, _ := proxy.New(upstream.URL, &evalConfigAndOPA{
		local: &rules.Config{},
		opa:   opaClient,
	})

	req := httptest.NewRequest("POST", "/graphql",
		bytes.NewReader([]byte(`{"query": "{ ok }"}`)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestFullPipeline_OPABlocks(t *testing.T) {
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result": {"allowed": false, "reason": "policy violation"}}`))
	}))
	defer opaSrv.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called")
	}))
	defer upstream.Close()

	opaClient := opa.New(opaSrv.URL)
	handler, _ := proxy.New(upstream.URL, &evalConfigAndOPA{
		local: &rules.Config{},
		opa:   opaClient,
	})

	req := httptest.NewRequest("POST", "/graphql",
		bytes.NewReader([]byte(`{"query": "{ hello }"}`)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestFullPipeline_InvalidGraphQL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called")
	}))
	defer upstream.Close()

	handler, _ := proxy.New(upstream.URL, &evalConfig{&rules.Config{}})

	req := httptest.NewRequest("POST", "/graphql",
		bytes.NewReader([]byte(`{"query": "{ invalid !!! }"}`)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestFullPipeline_BlockMutation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called")
	}))
	defer upstream.Close()

	cfg := &rules.Config{BlockedOperations: []string{"mutation"}}
	handler, _ := proxy.New(upstream.URL, &evalConfig{cfg})

	req := httptest.NewRequest("POST", "/graphql",
		bytes.NewReader([]byte(`{"query": "mutation { deleteUser(id: 1) { id } }"}`)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestFullPipeline_HealthPassthrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer upstream.Close()

	handler, _ := proxy.New(upstream.URL, &evalConfig{&rules.Config{}})
	req := httptest.NewRequest("GET", "/health", nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestFullPipeline_FieldAllowlist(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called")
	}))
	defer upstream.Close()

	cfg := &rules.Config{
		FieldAllowlist: []string{"user.name", "user.email"},
	}
	handler, _ := proxy.New(upstream.URL, &evalConfig{cfg})

	req := httptest.NewRequest("POST", "/graphql",
		bytes.NewReader([]byte(`{"query": "{ user { ssn } }"}`)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for field not in allowlist, got %d", resp.StatusCode)
	}
}
