package tenant

import (
	"net/http/httptest"
	"testing"
)

// ── R95: tenant identity provenance ─────────────────────────────────────────
// The header resolver must label what it produced so policy and telemetry can
// distinguish an asserted identity from a verified one.

func TestHeaderResolver_Present(t *testing.T) {
	req := httptest.NewRequest("POST", "/graphql", nil)
	req.Header.Set("X-API-Key", "acme_abc_secret")

	id, err := HeaderResolver{}.Resolve(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.TenantID != "acme_abc" {
		t.Errorf("tenant = %q, want %q", id.TenantID, "acme_abc")
	}
	if id.Source != SourceHeader {
		t.Errorf("source = %q, want %q — an unverified identity must be labelled as such", id.Source, SourceHeader)
	}
}

func TestHeaderResolver_Absent(t *testing.T) {
	req := httptest.NewRequest("POST", "/graphql", nil)
	id, err := HeaderResolver{}.Resolve(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.TenantID != "" {
		t.Errorf("tenant = %q, want empty", id.TenantID)
	}
	if id.Source != SourceNone {
		t.Errorf("source = %q, want %q", id.Source, SourceNone)
	}
}

func TestHeaderResolver_DuplicateHeaderUsesFirst(t *testing.T) {
	req := httptest.NewRequest("POST", "/graphql", nil)
	req.Header.Add("X-API-Key", "first_secret")
	req.Header.Add("X-API-Key", "second_secret")

	id, err := (HeaderResolver{}).Resolve(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.TenantID != "first" {
		t.Errorf("tenant = %q, want %q (Header.Get semantics)", id.TenantID, "first")
	}
}

func TestExtractTenantID(t *testing.T) {
	cases := []struct{ key, want string }{
		{"", ""},
		{"acme", "acme"},
		{"acme_secret", "acme"},
		{"acme_abc_secret", "acme_abc"},
		{"_secret", "_secret"},
		{"a_", "a_"},
		{"__x", "__x"},
		{"a__b", "a_"},
	}
	for _, c := range cases {
		if got := ExtractTenantID(c.key); got != c.want {
			t.Errorf("ExtractTenantID(%q) = %q, want %q", c.key, got, c.want)
		}
	}
}

// Unsupported modes must fail at startup rather than silently degrading to the
// unverified header resolver.
func TestResolverFor_Modes(t *testing.T) {
	for _, mode := range []string{"header", ""} {
		r, err := ResolverFor(mode, Options{})
		if err != nil {
			t.Errorf("ResolverFor(%q) returned error: %v", mode, err)
			continue
		}
		if _, ok := r.(HeaderResolver); !ok {
			t.Errorf("ResolverFor(%q) returned %T, want HeaderResolver", mode, r)
		}
	}
	for _, mode := range []string{"jwt", "mtls", "bogus"} {
		if _, err := ResolverFor(mode, Options{Secrets: []string{testSecret}}); err == nil {
			t.Errorf("ResolverFor(%q) accepted an unimplemented mode — startup must fail closed", mode)
		}
	}
	if _, err := ResolverFor("hmac", Options{Secrets: []string{testSecret}}); err != nil {
		t.Errorf("ResolverFor(hmac) rejected a valid secret: %v", err)
	}
}
