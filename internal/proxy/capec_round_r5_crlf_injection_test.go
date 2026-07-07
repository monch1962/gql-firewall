package proxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ──────────────────────────────────────────────────────────
// CAPEC Round 2: HTTP Request Splitting (R5 — Protocol & Communication)
//
// CAPEC-105: HTTP Request Splitting
// An adversary injects CRLF sequences into request headers to
// split the HTTP request stream and poison proxy caches or
// bypass security controls. For a reverse proxy, this means
// CRLF in header values reaching the upstream server.
// ──────────────────────────────────────────────────────────

// CAPEC-105: CRLF injection in Content-Type header value
// Go's httputil.ReverseProxy sanitizes header values before
// forwarding, replacing bare CR/LF with spaces. This test
// verifies that CRLF cannot reach the upstream via headers.
func TestAttack_CAPEC105_CRLFInContentType(t *testing.T) {
	var capturedHeaders http.Header
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	// Inject CRLF into Content-Type header — this should be
	// sanitized by Go's HTTP stack before it reaches the upstream
	body := bytes.NewReader([]byte(`{"query":"{ hello }"}`))
	req := httptest.NewRequest("POST", "/graphql", body)
	req.Header.Set("Content-Type", "application/json\r\nX-Injected: true")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// Verify the injected header does NOT appear at the upstream
	if capturedHeaders != nil {
		if injected := capturedHeaders.Get("X-Injected"); injected != "" {
			t.Errorf("CAPEC-105: CRLF injection succeeded — X-Injected header reached upstream: %q", injected)
		}
		if ct := capturedHeaders.Get("Content-Type"); ct != "application/json" {
			t.Logf("Content-Type at upstream: %q (may be sanitized by Go stdlib)", ct)
		}
		t.Log("CAPEC-105: CRLF in Content-Type blocked by Go HTTP stack")
	}
}

// CAPEC-105: CRLF injection in a custom header value
func TestAttack_CAPEC105_CRLFInCustomHeader(t *testing.T) {
	var capturedHeaders http.Header
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	body := bytes.NewReader([]byte(`{"query":"{ hello }"}`))
	req := httptest.NewRequest("POST", "/graphql", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Custom", "safe\r\nX-Spoofed: injected")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if capturedHeaders != nil {
		if injected := capturedHeaders.Get("X-Spoofed"); injected != "" {
			t.Errorf("CAPEC-105: CRLF injection via custom header — X-Spoofed reached upstream: %q", injected)
		}
		t.Log("CAPEC-105: CRLF in custom header blocked by Go HTTP stack")
	}
}

// CAPEC-105: CRLF injection in the request body (JSON with CRLF)
// This is a different attack surface — the JSON body shouldn't
// be interpreted as HTTP headers by the upstream.
func TestAttack_CAPEC105_CRLFInBody_Rejected(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	// JSON body with CRLF injection attempt — should be rejected
	// by the JSON decoder as invalid JSON
	body := bytes.NewReader([]byte("{\"query\": \"{hello}\"}\r\nHTTP/1.1 200 OK\r\n"))
	req := httptest.NewRequest("POST", "/graphql", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// The trailing garbage after the JSON object should be rejected
	if callCount > 0 {
		t.Errorf("CAPEC-105: request with body CRLF injection reached upstream %d times", callCount)
	}
	if w.Code != http.StatusBadRequest {
		t.Logf("CRLF body trailing garbage: got status %d", w.Code)
	}
}

// CAPEC-105: CRLF injection in the query parameter (GET request)
// httptest.NewRequest rejects CRLF in URLs, confirming Go's stdlib
// protects against this at the HTTP request construction level.
func TestAttack_CAPEC105_CRLFInQueryParam(t *testing.T) {
	// httptest.NewRequest panics on CRLF in URL — this is Go's protection
	defer func() {
		if r := recover(); r != nil {
			t.Log("CAPEC-105: CRLF in URL rejected by Go's HTTP request parser (inherently protected)")
		}
	}()

	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach upstream — CRLF should be rejected")
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)
	req := httptest.NewRequest("GET", "/graphql?query={hello}\r\nX-Injected:true", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	_ = w

	t.Error("should not reach here — NewRequest should have panicked")
}
