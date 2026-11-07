package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/monch1962/gql-firewall/internal/metrics"
	"github.com/monch1962/gql-firewall/internal/tenant"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// stubResolver returns a fixed identity so tests can prove the handler consults
// the configured resolver rather than parsing the header itself.
type stubResolver struct{ id tenant.Identity }

func (s stubResolver) Resolve(*http.Request) tenant.Identity { return s.id }

// ── R95: tenant identity comes from the configured resolver ─────────────────
// The handler must not re-derive tenancy from the raw header once a resolver is
// configured, or a future verified mode would be silently bypassed.
func TestAttack_HandlerUsesConfiguredTenantResolver(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	defer up.Close()

	ev := &captureEval{}
	h := MustNew(up.URL, ev)
	h.TenantResolver = stubResolver{id: tenant.Identity{TenantID: "resolved_tenant", Source: "hmac"}}

	req := httptest.NewRequest("POST", "/graphql", gql("{ hello }"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "header_tenant_secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if len(ev.calls) != 1 {
		t.Fatalf("expected 1 evaluation, got %d", len(ev.calls))
	}
	if got := ev.calls[0].TenantID; got != "resolved_tenant" {
		t.Errorf("tenant = %q, want %q — the header was parsed instead of using the resolver", got, "resolved_tenant")
	}
	if got := ev.calls[0].TenantIdentitySource; got != "hmac" {
		t.Errorf("identity source = %q, want %q — policies cannot gate on assurance level", got, "hmac")
	}
}

// The batch path must use the resolver too (R83 regression guard).
func TestAttack_BatchUsesConfiguredTenantResolver(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	defer up.Close()

	ev := &captureEval{}
	h := MustNew(up.URL, ev)
	h.TenantResolver = stubResolver{id: tenant.Identity{TenantID: "resolved_tenant", Source: "hmac"}}

	body, err := json.Marshal([]graphQLBody{{Query: "{ hello }"}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "header_tenant_secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if len(ev.calls) != 1 {
		t.Fatalf("expected 1 evaluation, got %d", len(ev.calls))
	}
	if got := ev.calls[0].TenantID; got != "resolved_tenant" {
		t.Errorf("batch tenant = %q, want %q", got, "resolved_tenant")
	}
	if got := ev.calls[0].TenantIdentitySource; got != "hmac" {
		t.Errorf("batch identity source = %q, want %q", got, "hmac")
	}
}

// ── R95: identity provenance is observable ─────────────────────────────────
// Operators need to see how much traffic presents an unverified identity, and
// to alert on a spike in unregistered tenant claims.
func TestAttack_TenantIdentityMetric(t *testing.T) {
	present := metrics.TenantIdentity.WithLabelValues("header", "present")
	absent := metrics.TenantIdentity.WithLabelValues("none", "absent")
	beforePresent, beforeAbsent := testutil.ToFloat64(present), testutil.ToFloat64(absent)

	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	defer up.Close()
	h := MustNew(up.URL, passEval)

	req := httptest.NewRequest("POST", "/graphql", gql("{ hello }"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "acme_secret")
	h.ServeHTTP(httptest.NewRecorder(), req)

	req = httptest.NewRequest("POST", "/graphql", gql("{ hello }"))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got := testutil.ToFloat64(present); got != beforePresent+1 {
		t.Errorf("tenant_identity_total{header,present} = %v, want %v", got, beforePresent+1)
	}
	if got := testutil.ToFloat64(absent); got != beforeAbsent+1 {
		t.Errorf("tenant_identity_total{none,absent} = %v, want %v", got, beforeAbsent+1)
	}
}
