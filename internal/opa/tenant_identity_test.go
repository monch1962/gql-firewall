package opa

import (
	"testing"

	"github.com/monch1962/gql-firewall/internal/parser"
)

// ── R95: identity provenance reaches policy ────────────────────────────────
// Policies must be able to see how the tenant identity was established and
// whether the claimed tenant is actually known to the firewall.
func TestBuildInput_TenantIdentityProvenance(t *testing.T) {
	store := NewDataStore()
	store.SetTenant("acme", map[string]interface{}{"depth_limit": 5.0})

	known := BuildInput(&parser.QueryInfo{
		TenantID:             "acme",
		TenantIdentitySource: "header",
		Depth:                1,
		FieldCount:           1,
		FieldPaths:           []string{"hello"},
	}, store)

	if known.TenantIdentitySource != "header" {
		t.Errorf("tenant_identity_source = %q, want %q", known.TenantIdentitySource, "header")
	}
	if !known.TenantKnown {
		t.Error("TenantKnown = false for a registered tenant")
	}
	if known.TenantConfig == nil {
		t.Error("TenantConfig missing for a registered tenant")
	}

	unknown := BuildInput(&parser.QueryInfo{
		TenantID:             "evil",
		TenantIdentitySource: "header",
		Depth:                1,
		FieldCount:           1,
		FieldPaths:           []string{"hello"},
	}, store)

	if unknown.TenantKnown {
		t.Error("TenantKnown = true for an unregistered tenant")
	}
	if unknown.TenantConfig != nil {
		t.Error("TenantConfig set for an unregistered tenant")
	}
	if unknown.TenantIdentitySource != "header" {
		t.Errorf("tenant_identity_source = %q, want %q", unknown.TenantIdentitySource, "header")
	}
}

// Anonymous requests must not be reported as a known tenant.
func TestBuildInput_AnonymousTenant(t *testing.T) {
	in := BuildInput(&parser.QueryInfo{
		Depth:      1,
		FieldCount: 1,
		FieldPaths: []string{"hello"},
	}, NewDataStore())

	if in.TenantKnown {
		t.Error("TenantKnown = true for an anonymous request")
	}
	if in.TenantIdentitySource != "" {
		t.Errorf("tenant_identity_source = %q, want empty", in.TenantIdentitySource)
	}
}
