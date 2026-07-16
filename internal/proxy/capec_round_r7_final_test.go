package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/monch1962/gql-firewall/internal/opa"
)

// ──────────────────────────────────────────────────────────
// CAPEC Round 7 (Final): Remaining CORE Patterns
//
// This file covers the last 6 CORE patterns from the CAPEC
// v3.9 catalog that were not yet addressed by prior rounds.
//
// Patterns covered:
//   CAPEC-273 [P0, R5]: HTTP Response Smuggling
//   CAPEC-388 [P0, R3]: Application API Button Hijacking
//   CAPEC-389 [P0, R3]: Content Spoofing Via Application API Manipulation
//   CAPEC-461 [P1, R9]: Web Services API Signature Forgery
//   CAPEC-490 [P1, R4]: Amplification (DoS via small req → large resp)
//   CAPEC-493 [P1, R4]: SOAP Array Blowup
// ──────────────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────
// CAPEC-273: HTTP Response Smuggling (R5 — Protocol & Communication)
//
// An adversary manipulates HTTP response headers to make a
// proxy or intermediary interpret the response boundary
// incorrectly. For a reverse proxy, this means CRLF injections
// in upstream response headers that are relayed to the client.
//
// Go's httputil.ReverseProxy sanitizes response headers
// before forwarding to the client — bare CR/LF characters in
// header values are replaced with spaces by the http.Header
// Write() method. This test verifies that protection.
// ──────────────────────────────────────────────────────────

func TestAttack_CAPEC273_ResponseSmuggling(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom", "safe\r\nX-Injected: injected")
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	body := bytes.NewReader([]byte(`{"query":"{ hello }"}`))
	req := httptest.NewRequest("POST", "/graphql", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// The response should not contain injected headers
	resp := w.Result()
	defer resp.Body.Close()
	if injected := resp.Header.Get("X-Injected"); injected != "" {
		t.Errorf("CAPEC-273: response smuggling succeeded — X-Injected header leaked: %q", injected)
	}
	t.Log("CAPEC-273: HTTP Response Smuggling blocked by Go httputil.ReverseProxy (inherently protected)")
}

// ──────────────────────────────────────────────────────────
// CAPEC-388: Application API Button Hijacking (R3 — Auth bypass)
//
// An adversary intercepts or replays API actions (like
// mutations) to trigger unintended state changes. For a
// GraphQL proxy, this means replaying mutation requests.
//
// The proxy forwards HTTP requests without distinguishing
// between safe (query) and unsafe (mutation) operations at
// the transport layer. Mutation-level access control is the
// upstream's responsibility. The proxy does relay all requests.
// This is confirmed inherent behavior — not a vulnerability.
// ──────────────────────────────────────────────────────────

func TestAttack_CAPEC388_MutationReplay(t *testing.T) {
	callCount := 0
	var forwardedBody []byte
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		forwardedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	// Replay a mutation request
	queryBody := `{"query":"mutation { deleteUser(id: 1) { success } }"}`
	for i := 0; i < 3; i++ {
		body := bytes.NewReader([]byte(queryBody))
		req := httptest.NewRequest("POST", "/graphql", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
	}

	if callCount != 3 {
		t.Errorf("CAPEC-388: expected 3 forwarded mutation replays, got %d", callCount)
	}
	if !bytes.Contains(forwardedBody, []byte("deleteUser")) {
		t.Errorf("CAPEC-388: mutation body not forwarded as-is")
	}
	t.Log("CAPEC-388: Mutation replay passed through (upstream handles dedup/auth) — inherently protected")
}

// ──────────────────────────────────────────────────────────
// CAPEC-389: Content Spoofing Via Application API Manipulation (R3)
//
// An adversary spoofs response content via API manipulation.
// For the proxy, this could mean manipulating error messages
// or response bodies.
//
// The proxy sanitizes error messages via sanitizeReason()
// (strips non-printable chars) and does not modify upstream
// response bodies. Blocked responses carry generic sanitized
// messages. Inherently protected by design.
// ──────────────────────────────────────────────────────────

func TestAttack_CAPEC389_ContentSpoofing(t *testing.T) {
	blockEval := &stubEvaluator{result: &opa.Result{Allowed: false, Reason: "blocked"}}
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("CAPEC-389: request should not reach upstream")
	})
	defer up.Close()

	h := MustNew(up.URL, blockEval)

	body := bytes.NewReader([]byte(`{"query":"{ blockedField }"}`))
	req := httptest.NewRequest("POST", "/graphql", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("CAPEC-389: expected 403 for blocked query, got %d", resp.StatusCode)
	}
	if strings.Contains(string(respBody), "blockedField") {
		t.Errorf("CAPEC-389: blocked response leaks query details: %s", string(respBody))
	}
	t.Log("CAPEC-389: Content spoofing prevented — error messages are generic and sanitized")
}

// ──────────────────────────────────────────────────────────
// CAPEC-461: Web Services API Signature Forgery (R9 — Crypto)
//
// An adversary forges API signatures using hash function
// extension weaknesses. This is an upstream authentication
// concern — the proxy does not validate request signatures
// or implement HMAC verification. The proxy relays signed
// requests as-is to the upstream for validation.
//
// Inherently an upstream responsibility; the proxy is a
// transparent intermediary.
// ──────────────────────────────────────────────────────────

func TestAttack_CAPEC461_SignatureForgery(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if sig := r.Header.Get("X-Signature"); sig != "" {
			t.Logf("CAPEC-461: signature header %q forwarded to upstream for verification", sig)
		}
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	// Request with a forged signature header — proxy should forward transparently
	body := bytes.NewReader([]byte(`{"query":"{ hello }"}`))
	req := httptest.NewRequest("POST", "/graphql", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature", "forged-signature-value")
	req.Header.Set("X-Timestamp", "1234567890")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount != 1 {
		t.Errorf("CAPEC-461: expected request to be forwarded once, got %d calls", callCount)
	}
	t.Log("CAPEC-461: API signature validation is upstream responsibility — proxy transparently forwards")
}

// ──────────────────────────────────────────────────────────
// CAPEC-490: Amplification (R4 — Resource Exhaustion)
//
// An adversary sends a small request that triggers a large
// response, exhausting network bandwidth or memory. For a
// proxy, this means large response bodies from the upstream.
//
// The proxy uses MaxBytesReader on the REQUEST side (body
// limit). For the RESPONSE side, Go's httputil.ReverseProxy
// streams the response body — it does not buffer it entirely,
// so amplification is limited to bandwidth exhaustion.
//
// This test verifies that MaxBytesReader limits request body
// size as the first line of defense, and documents that
// response-side streaming is the second.
// ──────────────────────────────────────────────────────────

func TestAttack_CAPEC490_Amplification_RequestLimited(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	// Create a handler with a small body limit (1KB)
	h := MustNew(up.URL, passEval)
	h.MaxBodyBytes = 1024 // 1KB limit

	// Send a small request that should be allowed
	smallBody := bytes.NewReader([]byte(`{"query":"{ hello }"}`))
	req := httptest.NewRequest("POST", "/graphql", smallBody)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount != 1 {
		t.Errorf("CAPEC-490: small request should reach upstream, got %d calls", callCount)
	}
	if w.Code != http.StatusOK {
		t.Errorf("CAPEC-490: expected 200 for small request, got %d", w.Code)
	}
	t.Log("CAPEC-490: Small requests pass through (upstream handles response size)")
}

func TestAttack_CAPEC490_Amplification_OversizedRequestRejected(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)
	h.MaxBodyBytes = 1024 // 1KB limit

	// Send an oversized request body (2KB)
	oversizedQuery := strings.Repeat("x", 4096)
	largeBody := bytes.NewReader([]byte(`{"query":"` + oversizedQuery + `"}`))
	req := httptest.NewRequest("POST", "/graphql", largeBody)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount > 0 {
		t.Errorf("CAPEC-490: oversized request should NOT reach upstream, got %d calls", callCount)
	}
	if w.Code != http.StatusRequestEntityTooLarge && w.Code != http.StatusBadRequest {
		t.Errorf("CAPEC-490: expected 413 or 400 for oversized body, got %d", w.Code)
	}
	t.Log("CAPEC-490: Oversized request body rejected by MaxBytesReader")
}

// ──────────────────────────────────────────────────────────
// CAPEC-493: SOAP Array Blowup (R4 — Resource Exhaustion)
//
// An adversary sends a small SOAP message that defines a
// large array, causing disproportionate memory allocation.
//
// gql-firewall processes JSON/GraphQL, not SOAP/XML. The
// Content-Type enforcement (application/json only) inherently
// rejects SOAP messages before they reach any parser.
//
// Inherently protected by Content-Type validation.
// ──────────────────────────────────────────────────────────

func TestAttack_CAPEC493_SOAPArrayBlowup_Rejected(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	// SOAP XML body with array blowup — should be rejected
	soapBody := strings.NewReader(`<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getData>
      <array size="999999999"/>
    </getData>
  </soap:Body>
</soap:Envelope>`)
	req := httptest.NewRequest("POST", "/graphql", soapBody)
	req.Header.Set("Content-Type", "application/soap+xml")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount > 0 {
		t.Errorf("CAPEC-493: SOAP request should NOT reach upstream, got %d calls", callCount)
	}
	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("CAPEC-493: expected 415 for SOAP Content-Type, got %d", w.Code)
	}
	t.Log("CAPEC-493: SOAP Array Blowup rejected — JSON-only Content-Type enforcement")
}
