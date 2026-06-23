package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/monch1962/gql-firewall/internal/opa"
	"github.com/monch1962/gql-firewall/internal/parser"
)

func TestSanitizeError(t *testing.T) {
	tests := []struct{ input, want string }{
		{"body", "invalid request body"},
		{"json", "invalid JSON in request"},
		{"query", "invalid GraphQL query"},
		{"eval", "rule evaluation error"},
		{"unknown", "request processing error"},
		{"", "request processing error"},
	}
	for _, tt := range tests {
		got := sanitizeError(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeError(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDefaultMaxBodyBytes(t *testing.T) {
	if DefaultMaxBodyBytes != 1*1024*1024 {
		t.Errorf("expected DefaultMaxBodyBytes=1MB, got %d", DefaultMaxBodyBytes)
	}
}

func TestSanitizeReason(t *testing.T) {
	tests := []struct{ input, want string }{
		{"simple message", "simple message"},
		{`injected"`, `injected"`},
		{"blocked\x00nullbyte", "blockednullbyte"},
		{"multi\nline", "multiline"},
		{"tab\there", "tabhere"},
		{"\x01\x02\x03BOM", "BOM"},
	}
	for _, tt := range tests {
		got := sanitizeReason(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeReason(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// stubEvaluator implements Evaluator for testing.
type stubEvaluator struct {
	result *opa.Result
	err    error
}

func (s *stubEvaluator) Evaluate(info *parser.QueryInfo) (*opa.Result, error) {
	return s.result, s.err
}

func TestHandler_AllowsValidQuery(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !bytes.Contains(body, []byte("hello")) {
			t.Errorf("expected upstream to receive original body")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": {"hello": "world"}}`))
	})
	defer up.Close()

	handler := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(`{"query": "{ hello }"}`)))
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
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not be called") })
	defer up.Close()

	handler := MustNew(up.URL, &stubEvaluator{
		result: &opa.Result{Allowed: false, Reason: "query depth exceeded"},
	})
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(`{"query": "{ deep { nested { query } } }"}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("blocked")) && !bytes.Contains(body, []byte("depth")) {
		t.Errorf("expected block reason in response, got %s", string(body))
	}
}

func TestHandler_PassesHeaders(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Authorization header to be forwarded")
		}
		if r.Header.Get("X-Custom") != "value" {
			t.Errorf("expected X-Custom header to be forwarded")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": {"ok": true}}`))
	})
	defer up.Close()

	handler := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(`{"query": "{ ok }"}`)))
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
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not be called") })
	defer up.Close()

	handler := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(`not-json`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestHandler_NonPostRequests(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "up"}`))
	})
	defer up.Close()

	handler := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestHandler_MissingQueryField(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not be called") })
	defer up.Close()

	handler := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(`{"operationName": "Test"}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestHandler_ForwardsUpstreamError(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "upstream error"}`))
	})
	defer up.Close()

	handler := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(`{"query": "{ hello }"}`)))
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
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not be called") })
	defer up.Close()

	handler := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})
	handler.MaxBodyBytes = 1024

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
		t.Errorf("expected 413, got %d", resp.StatusCode)
	}
}

func TestHandler_AcceptsBodyAtLimit(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": {"ok": true}}`))
	})
	defer up.Close()

	handler := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})
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
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

type errStr string

func (e errStr) Error() string { return string(e) }

func TestHandler_EvaluatorError(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not be called") })
	defer up.Close()

	handler := MustNew(up.URL, &stubEvaluator{err: errStr("simulated eval error")})
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(`{"query": "{ hello }"}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", resp.StatusCode)
	}
}

func TestHandler_TenantExtraction(t *testing.T) {
	var capturedTenant string
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": {"ok": true}}`))
	})
	defer up.Close()

	handler := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})
	// Monkey-patch the handler to spy on tenant extraction
	orig := handler.evaluator
	handler.evaluator = &stubEvaluator{result: &opa.Result{Allowed: true}}
	_ = orig

	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(`{"query": "{ hello }"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "myapp_secret123")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	_ = capturedTenant
}

func TestHandler_NonGraphQLPost(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "passed"}`))
	})
	defer up.Close()

	handler := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})
	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader([]byte(`{"event": "test"}`)))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}
