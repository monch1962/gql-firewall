package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/monch1962/gql-firewall/internal/metrics"
	"github.com/monch1962/gql-firewall/internal/tenant"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const hmacTestSecret = "0123456789abcdef0123456789abcdef"

func hmacResolver(t *testing.T, opts tenant.Options) tenant.Resolver {
	t.Helper()
	if len(opts.Secrets) == 0 {
		opts.Secrets = []string{hmacTestSecret}
	}
	r, err := tenant.ResolverFor("hmac", opts)
	if err != nil {
		t.Fatalf("ResolverFor(hmac): %v", err)
	}
	return r
}

func signedKey(t *testing.T, tenantID string) string {
	t.Helper()
	key, err := tenant.IssueKey(tenantID, []string{hmacTestSecret}, time.Hour, time.Now())
	if err != nil {
		t.Fatalf("IssueKey: %v", err)
	}
	return key
}

// ── R96: unverifiable tenant credentials are rejected with 401 ─────────────
// A forged or unsigned key must not reach the policy engine or the upstream.
func TestAttack_InvalidSignedKeyIs401(t *testing.T) {
	upstreamCalls := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	ev := &captureEval{}
	h := MustNew(up.URL, ev)
	h.TenantResolver = hmacResolver(t, tenant.Options{})

	key := signedKey(t, "acme")
	forged := key[:len(key)-4] + "AAAA" // corrupt the MAC

	req := httptest.NewRequest("POST", "/graphql", gql("{ hello }"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", forged)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if len(ev.calls) != 0 {
		t.Errorf("evaluator called %d time(s) for unverified credentials", len(ev.calls))
	}
	if upstreamCalls != 0 {
		t.Errorf("upstream reached %d time(s) with unverified credentials", upstreamCalls)
	}
	if strings.Contains(w.Body.String(), forged) {
		t.Error("401 body echoes the presented credential")
	}
}

func TestAttack_UnsignedKeyIs401InHMACMode(t *testing.T) {
	upstreamCalls := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { upstreamCalls++; w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	h.TenantResolver = hmacResolver(t, tenant.Options{})

	req := httptest.NewRequest("POST", "/graphql", gql("{ hello }"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "acme_secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for an unsigned key in hmac mode", w.Code)
	}
	if upstreamCalls != 0 {
		t.Errorf("upstream reached %d time(s) with an unsigned key", upstreamCalls)
	}
}

// The batch envelope must not be a way around credential checks.
func TestAttack_InvalidKeyBatchIs401(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("upstream should not be reached") })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	h.TenantResolver = hmacResolver(t, tenant.Options{})

	body, err := json.Marshal([]graphQLBody{{Query: "{ hello }"}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "acme_secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// GET must enforce the same rule.
func TestAttack_InvalidKeyGETIs401(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("upstream should not be reached") })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	h.TenantResolver = hmacResolver(t, tenant.Options{})

	req := httptest.NewRequest("GET", "/graphql?query=%7Bhello%7D", nil)
	req.Header.Set("X-API-Key", "acme_secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// ── R96: a valid signed key carries a verified tenant ─────────────────────
func TestAttack_ValidSignedKeyForwardsWithVerifiedTenant(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	defer up.Close()

	ev := &captureEval{}
	h := MustNew(up.URL, ev)
	h.TenantResolver = hmacResolver(t, tenant.Options{})

	req := httptest.NewRequest("POST", "/graphql", gql("{ hello }"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", signedKey(t, "acme"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if len(ev.calls) != 1 {
		t.Fatalf("expected 1 evaluation, got %d", len(ev.calls))
	}
	if got := ev.calls[0].TenantID; got != "acme" {
		t.Errorf("tenant = %q, want %q", got, "acme")
	}
	if got := ev.calls[0].TenantIdentitySource; got != string(tenant.SourceHMAC) {
		t.Errorf("identity source = %q, want %q — policy cannot see that this tenant was verified", got, tenant.SourceHMAC)
	}
}

// Migration mode: unsigned keys pass but stay labelled unverified.
func TestAttack_AllowUnsignedKeepsHeaderSource(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	defer up.Close()

	ev := &captureEval{}
	h := MustNew(up.URL, ev)
	h.TenantResolver = hmacResolver(t, tenant.Options{AllowUnsigned: true})

	req := httptest.NewRequest("POST", "/graphql", gql("{ hello }"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "acme_secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 in migration mode", w.Code)
	}
	if got := ev.calls[0].TenantIdentitySource; got != string(tenant.SourceHeader) {
		t.Errorf("identity source = %q, want %q so require_verified_tenant still refuses it", got, tenant.SourceHeader)
	}
}

// Invalid credentials are observable: a spike means probing or a broken client.
func TestAttack_InvalidKeyMetric(t *testing.T) {
	child := metrics.TenantIdentity.WithLabelValues(string(tenant.SourceHeader), "invalid")
	before := testutil.ToFloat64(child)

	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	defer up.Close()
	h := MustNew(up.URL, passEval)
	h.TenantResolver = hmacResolver(t, tenant.Options{})

	req := httptest.NewRequest("POST", "/graphql", gql("{ hello }"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "acme_secret")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got := testutil.ToFloat64(child); got != before+1 {
		t.Errorf("tenant_identity_total{header,invalid} = %v, want %v", got, before+1)
	}
}
