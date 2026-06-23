package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/monch1962/gql-firewall/internal/opa"
	"github.com/monch1962/gql-firewall/internal/parser"
)

// stubPanicEval simulates a panicking evaluator to test recovery.
type stubPanicEval struct{}

func (s *stubPanicEval) Evaluate(info *parser.QueryInfo) (*opa.Result, error) {
	panic("simulated evaluator panic")
}

// ── H1: Panic recovery ─────────────────────────────────────────────────────

func TestHardening_PanicInEvaluator_Returns500(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach upstream")
	})
	defer up.Close()

	h := MustNew(up.URL, &stubPanicEval{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	body := mustJSON(graphQLBody{Query: "{ hello }"})
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	resp := w.Result()
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 after panic, got %d: %s", resp.StatusCode, string(bodyBytes))
	}
	if !json.Valid(bodyBytes) {
		t.Errorf("response after panic is not valid JSON: %s", string(bodyBytes))
	}
}

func TestHardening_PanicInNonGraphQLPath_DoesNotCrash(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})
	defer up.Close()

	// Using a nil evaluator will cause panic on GraphQL path but non-GraphQL should pass
	h := MustNew(up.URL, &stubPanicEval{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Non-GraphQL GET request should pass through regardless of evaluator state
	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for non-GraphQL path, got %d", resp.StatusCode)
	}
}

// ── H2: Security headers ───────────────────────────────────────────────────

func TestHardening_SecurityHeadersOnBlockedResponse(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach upstream")
	})
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: false, Reason: "denied"}})
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(mustJSON(graphQLBody{Query: "{ hello }"})))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	resp := w.Result()
	resp.Body.Close()

	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("expected X-Content-Type-Options: nosniff, got %q", resp.Header.Get("X-Content-Type-Options"))
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("expected X-Frame-Options: DENY, got %q", resp.Header.Get("X-Frame-Options"))
	}
}

func TestHardening_SecurityHeadersOnAllowedResponse(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "override") // should be overridden by proxy
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"ok":true}}`))
	})
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(mustJSON(graphQLBody{Query: "{ hello }"})))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	resp := w.Result()
	resp.Body.Close()

	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("expected X-Content-Type-Options: nosniff, got %q", resp.Header.Get("X-Content-Type-Options"))
	}
}

// ── H3: Stricter Content-Type enforcement ───────────────────────────────────

func TestHardening_WrongContentType_415(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach upstream")
	})
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(mustJSON(graphQLBody{Query: "{ hello }"})))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	resp := w.Result()
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415 for wrong content type, got %d", resp.StatusCode)
	}
}

func TestHardening_ContentTypeWithCharset_Accepted(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"ok":true}}`))
	})
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(mustJSON(graphQLBody{Query: "{ hello }"})))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	resp := w.Result()
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for application/json with charset, got %d", resp.StatusCode)
	}
}

// ── H4: Oversized body rejected ────────────────────────────────────────────

func TestHardening_OversizedBody_413(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach upstream")
	})
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})
	h.MaxBodyBytes = 100

	bodyStr := `{"query":"` + strings.Repeat("x", 200) + `"}`
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(bodyStr)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	resp := w.Result()
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 for oversized body, got %d", resp.StatusCode)
	}
}

// ── H5: Path traversal protection ──────────────────────────────────────────

func TestHardening_PathTraversal_NotInspected(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		// Path traversal should pass through to upstream, not be inspected
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"passed":true}`))
	})
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: false, Reason: "would block"}})
	req := httptest.NewRequest("POST", "/graphql/../admin/config", bytes.NewReader(mustJSON(graphQLBody{Query: "{ hello }"})))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	resp := w.Result()
	resp.Body.Close()
	// Should pass through (200 from upstream), not be inspected and blocked (403)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 (pass-through) for traversal path, got %d", resp.StatusCode)
	}
}
