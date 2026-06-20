package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/monch1962/gql-firewall/internal/parser"
	"github.com/monch1962/gql-firewall/internal/rules"
)

func TestSanitizeError(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"body", "invalid request body"},
		{"json", "invalid JSON in request"},
		{"query", "invalid GraphQL query"},
		{"eval", "rule evaluation error"},
		{"unknown", "request processing error"},
		{"", "request processing error"},
	}
	for _, tt := range tests {
		got := sanitizeError(tt.input)
		if got != tt.expected {
			t.Errorf("sanitizeError(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestDefaultMaxBodyBytes(t *testing.T) {
	if DefaultMaxBodyBytes != 1*1024*1024 {
		t.Errorf("expected DefaultMaxBodyBytes=1MB, got %d", DefaultMaxBodyBytes)
	}
}

type stubEvaluator struct {
	result *rules.Result
	err    error
	// Optional hook to inspect the QueryInfo during evaluation
	evaluateHook func(*parser.QueryInfo)
}

func (s *stubEvaluator) Evaluate(info *parser.QueryInfo) (*rules.Result, error) {
	if s.evaluateHook != nil {
		s.evaluateHook(info)
	}
	return s.result, s.err
}

func TestHandler_AllowsValidQuery(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !bytes.Contains(body, []byte("hello")) {
			t.Errorf("expected upstream to receive original body")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": {"hello": "world"}}`))
	}))
	defer upstream.Close()

	handler := New(upstream.URL, &stubEvaluator{result: &rules.Result{Allowed: true}})

	reqBody := `{"query": "{ hello }"}`
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(reqBody)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("world")) {
		t.Errorf("expected upstream response body, got %s", string(body))
	}
}

func TestHandler_BlocksQuery(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called for blocked query")
	}))
	defer upstream.Close()

	handler := New(upstream.URL, &stubEvaluator{
		result: &rules.Result{
			Allowed: false,
			Reason:  "query depth exceeded",
		},
	})

	reqBody := `{"query": "{ deep { nested { query } } }"}`
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(reqBody)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("blocked")) && !bytes.Contains(body, []byte("depth")) {
		t.Errorf("expected block reason in response body, got %s", string(body))
	}
}

func TestHandler_PassesHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Authorization header to be forwarded")
		}
		if r.Header.Get("X-Custom") != "value" {
			t.Errorf("expected X-Custom header to be forwarded")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": {"ok": true}}`))
	}))
	defer upstream.Close()

	handler := New(upstream.URL, &stubEvaluator{result: &rules.Result{Allowed: true}})

	reqBody := `{"query": "{ ok }"}`
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(reqBody)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("X-Custom", "value")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestHandler_InvalidRequestBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called for invalid body")
	}))
	defer upstream.Close()

	handler := New(upstream.URL, &stubEvaluator{result: &rules.Result{Allowed: true}})

	reqBody := `not-json`
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(reqBody)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid body, got %d", resp.StatusCode)
	}
}

func TestHandler_NonPostRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "up"}`))
	}))
	defer upstream.Close()

	handler := New(upstream.URL, &stubEvaluator{result: &rules.Result{Allowed: true}})

	// GET request should pass through without evaluation
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestHandler_MissingQueryField(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called")
	}))
	defer upstream.Close()

	handler := New(upstream.URL, &stubEvaluator{result: &rules.Result{Allowed: true}})

	// Valid JSON but missing "query" field
	reqBody := `{"operationName": "Test", "variables": {}}`
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(reqBody)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for missing query field, got %d", resp.StatusCode)
	}
}

func TestHandler_ForwardsUpstreamError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "upstream error"}`))
	}))
	defer upstream.Close()

	handler := New(upstream.URL, &stubEvaluator{result: &rules.Result{Allowed: true}})

	reqBody := `{"query": "{ hello }"}`
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(reqBody)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("upstream error")) {
		t.Errorf("expected upstream error in response, got %s", string(body))
	}
}

func TestHandler_RejectsOversizedBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called")
	}))
	defer upstream.Close()

	handler := New(upstream.URL, &stubEvaluator{result: &rules.Result{Allowed: true}})
	handler.MaxBodyBytes = 1024 // 1KB limit for test

	// Create a body larger than limit
	largeBody := make([]byte, 2048)
	for i := range largeBody {
		largeBody[i] = 'a'
	}
	bodyStr := `{"query": "` + string(largeBody) + `"}`

	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(bodyStr)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 for oversized body, got %d", resp.StatusCode)
	}
}

func TestHandler_AcceptsBodyAtLimit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": {"ok": true}}`))
	}))
	defer upstream.Close()

	handler := New(upstream.URL, &stubEvaluator{result: &rules.Result{Allowed: true}})
	handler.MaxBodyBytes = 1024

	bodyContent := make([]byte, 900)
	for i := range bodyContent {
		bodyContent[i] = 'x'
	}
	bodyStr := `{"query": "{ ` + string(bodyContent) + ` }"}`

	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(bodyStr)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for body at limit, got %d", resp.StatusCode)
	}
}

func TestHandler_EvaluatorError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called on eval error")
	}))
	defer upstream.Close()

	handler := New(upstream.URL, &stubEvaluator{err: assertAnError{}})

	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(`{"query": "{ hello }"}`)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 for eval error, got %d", resp.StatusCode)
	}
}

type assertAnError struct{}

func (a assertAnError) Error() string { return "simulated eval error" }

func TestHandler_TenantExtraction(t *testing.T) {
	capturedTenant := ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": {"ok": true}}`))
	}))
	defer upstream.Close()

	handler := New(upstream.URL, &stubEvaluator{
		result: &rules.Result{Allowed: true},
		evaluateHook: func(info *parser.QueryInfo) {
			capturedTenant = info.TenantID
		},
	})

	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(`{"query": "{ hello }"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "myapp_secret123")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if capturedTenant != "myapp" {
		t.Errorf("expected tenant 'myapp', got %q", capturedTenant)
	}
}

func TestHandler_NonGraphQLPost(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "passed"}`))
	}))
	defer upstream.Close()

	handler := New(upstream.URL, &stubEvaluator{result: &rules.Result{Allowed: true}})

	// POST to non-/graphql path should pass through without evaluation
	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader([]byte(`{"event": "test"}`)))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for non-graphql POST, got %d", resp.StatusCode)
	}
}
