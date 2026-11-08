package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/monch1962/gql-firewall/internal/tenant"
)

// ── R97: ambiguous credentials must not reach the policy engine ────────────
// The resolver refuses duplicate/comma-joined X-API-Key values; the proxy must
// translate that into a 401 before evaluation and before forwarding, so the
// upstream never sees a credential the firewall did not police.

func TestAttack_DuplicateAPIKeyHeadersAre401(t *testing.T) {
	upstreamCalls := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	ev := &captureEval{}
	h := MustNew(up.URL, ev)
	h.TenantResolver = hmacResolver(t, tenant.Options{})

	req := httptest.NewRequest("POST", "/graphql", gql("{ hello }"))
	req.Header.Set("Content-Type", "application/json")
	// A valid signed key in the first position plus an attacker-chosen second
	// value: a folding proxy can authenticate the second principal.
	req.Header.Add("X-API-Key", signedKey(t, "acme"))
	req.Header.Add("X-API-Key", "bob_secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for duplicate credential headers", w.Code)
	}
	if len(ev.calls) != 0 {
		t.Errorf("evaluator called %d time(s) with an ambiguous credential", len(ev.calls))
	}
	if upstreamCalls != 0 {
		t.Errorf("upstream reached %d time(s) with an ambiguous credential", upstreamCalls)
	}
}

func TestAttack_CommaJoinedAPIKeyIs401(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be reached with a comma-joined credential")
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)
	h.TenantResolver = tenant.HeaderResolver{}

	req := httptest.NewRequest("POST", "/graphql", gql("{ hello }"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "acme_secret,bob_secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestAttack_OversizedAPIKeyIs401(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be reached with an oversized credential")
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)
	h.TenantResolver = hmacResolver(t, tenant.Options{})

	req := httptest.NewRequest("POST", "/graphql", gql("{ hello }"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "v1."+strings.Repeat("A", tenant.MaxCredentialLen))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for an oversized credential", w.Code)
	}
}

// GET and batch envelopes must enforce the same rule as POST.
func TestAttack_AmbiguousKeyOnGETAndBatchIs401(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be reached")
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)
	h.TenantResolver = hmacResolver(t, tenant.Options{})

	t.Run("GET", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/graphql?query=%7Bhello%7D", nil)
		req.Header.Add("X-API-Key", signedKey(t, "acme"))
		req.Header.Add("X-API-Key", "bob_secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("GET status = %d, want 401", w.Code)
		}
	})

	t.Run("batch", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/graphql", strings.NewReader(`[{"query":"{ hello }"}]`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Add("X-API-Key", signedKey(t, "acme"))
		req.Header.Add("X-API-Key", "bob_secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("batch status = %d, want 401", w.Code)
		}
	})
}
