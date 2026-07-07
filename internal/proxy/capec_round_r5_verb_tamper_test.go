package proxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/monch1962/gql-firewall/internal/opa"
)

// ──────────────────────────────────────────────────────────
// CAPEC Round 1: HTTP Verb Tampering (R5 — Protocol & Communication)
//
// These tests verify that all HTTP methods to /graphql are
// evaluated by the firewall, preventing bypass via verb tampering.
// ──────────────────────────────────────────────────────────

// CAPEC-274: HTTP Verb Tampering
// Mechanism: Protocol & Communication (R5)
// An adversary uses an unexpected HTTP method (PUT, DELETE, PATCH,
// OPTIONS, HEAD, TRACE, CONNECT) to bypass firewall controls on /graphql.
func TestAttack_CAPEC274_PUTBypass(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: false, Reason: "blocked"}})
	body := bytes.NewReader([]byte(`{"query":"{ hello }"}`))
	req := httptest.NewRequest("PUT", "/graphql", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount > 0 {
		t.Errorf("CAPEC-274: PUT to /graphql reached upstream %d times (should be blocked)", callCount)
	}
	if w.Code != http.StatusForbidden && w.Code != http.StatusBadRequest && w.Code != http.StatusMethodNotAllowed {
		t.Errorf("CAPEC-274: expected 4xx for PUT to /graphql, got %d", w.Code)
	}
}

// CAPEC-274: HTTP Verb Tampering — DELETE method bypass
func TestAttack_CAPEC274_DELETEBypass(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: false, Reason: "blocked"}})
	req := httptest.NewRequest("DELETE", "/graphql", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount > 0 {
		t.Errorf("CAPEC-274: DELETE to /graphql reached upstream %d times (should be blocked)", callCount)
	}
	if w.Code != http.StatusForbidden && w.Code != http.StatusBadRequest && w.Code != http.StatusMethodNotAllowed {
		t.Errorf("CAPEC-274: expected 4xx for DELETE to /graphql, got %d", w.Code)
	}
}

// CAPEC-274: HTTP Verb Tampering — PATCH method bypass
func TestAttack_CAPEC274_PATCHBypass(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: false, Reason: "blocked"}})
	body := bytes.NewReader([]byte(`{"query":"{ hello }"}`))
	req := httptest.NewRequest("PATCH", "/graphql", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount > 0 {
		t.Errorf("CAPEC-274: PATCH to /graphql reached upstream %d times (should be blocked)", callCount)
	}
	if w.Code != http.StatusForbidden && w.Code != http.StatusBadRequest && w.Code != http.StatusMethodNotAllowed {
		t.Errorf("CAPEC-274: expected 4xx for PATCH to /graphql, got %d", w.Code)
	}
}

// CAPEC-274: HTTP Verb Tampering — OPTIONS method bypass
func TestAttack_CAPEC274_OPTIONSBypass(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: false, Reason: "blocked"}})
	req := httptest.NewRequest("OPTIONS", "/graphql", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount > 0 {
		t.Errorf("CAPEC-274: OPTIONS to /graphql reached upstream %d times (should be blocked)", callCount)
	}
	if w.Code != http.StatusForbidden && w.Code != http.StatusBadRequest && w.Code != http.StatusMethodNotAllowed {
		t.Errorf("CAPEC-274: expected 4xx for OPTIONS to /graphql, got %d", w.Code)
	}
}

// CAPEC-274: HTTP Verb Tampering — TRACE method bypass
func TestAttack_CAPEC274_TRACEBypass(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: false, Reason: "blocked"}})
	req := httptest.NewRequest("TRACE", "/graphql", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount > 0 {
		t.Errorf("CAPEC-274: TRACE to /graphql reached upstream %d times (should be blocked)", callCount)
	}
	if w.Code != http.StatusForbidden && w.Code != http.StatusBadRequest && w.Code != http.StatusMethodNotAllowed {
		t.Errorf("CAPEC-274: expected 4xx for TRACE to /graphql, got %d", w.Code)
	}
}

// CAPEC-274: HTTP Verb Tampering — HEAD method bypass
func TestAttack_CAPEC274_HEADBypass(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: false, Reason: "blocked"}})
	req := httptest.NewRequest("HEAD", "/graphql", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount > 0 {
		t.Errorf("CAPEC-274: HEAD to /graphql reached upstream %d times (should be blocked)", callCount)
	}
	if w.Code != http.StatusForbidden && w.Code != http.StatusBadRequest && w.Code != http.StatusMethodNotAllowed {
		t.Errorf("CAPEC-274: expected 4xx for HEAD to /graphql, got %d", w.Code)
	}
}

// CAPEC-274: Verb tampering also allows method=GET+body to bypass POST content-type checks
// This tests that methods other than GET/POST on non-graphql paths still pass through
func TestAttack_CAPEC274_NonGraphQLPath_passthrough(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)
	req := httptest.NewRequest("PUT", "/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount != 1 {
		t.Errorf("expected non-graphql PUT to pass through, upstream called %d times", callCount)
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for non-graphql PUT, got %d", w.Code)
	}
}

// Test that POST with a blocked evaluator correctly returns 403 (regression check)
func TestAttack_CAPEC274_POSTStillBlocked(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: false, Reason: "blocked"}})
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(`{"query":"{ hello }"}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount > 0 {
		t.Errorf("POST to /graphql with blocked evaluator reached upstream %d times", callCount)
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for blocked POST, got %d", w.Code)
	}
}
