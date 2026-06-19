package tenant

import (
	"testing"

	"github.com/monch1962/gql-firewall/internal/rules"
)

func TestNew(t *testing.T) {
	s := New(nil)
	if s == nil {
		t.Fatal("expected non-nil store")
	}
	if c := s.Count(); c != 0 {
		t.Errorf("expected 0 tenants, got %d", c)
	}
}

func TestGetDefault(t *testing.T) {
	defaultCfg := &rules.Config{DepthLimit: 5}
	s := New(defaultCfg)

	cfg := s.Get("unknown-tenant")
	if cfg.DepthLimit != 5 {
		t.Errorf("expected DepthLimit=5 from default, got %d", cfg.DepthLimit)
	}
}

func TestGetAndSet(t *testing.T) {
	s := New(&rules.Config{DepthLimit: 10})

	tenantCfg := &rules.Config{DepthLimit: 3, MaxFieldCount: 50}
	s.Set("tenant-alpha", tenantCfg)

	cfg := s.Get("tenant-alpha")
	if cfg.DepthLimit != 3 {
		t.Errorf("expected DepthLimit=3, got %d", cfg.DepthLimit)
	}
	if cfg.MaxFieldCount != 50 {
		t.Errorf("expected MaxFieldCount=50, got %d", cfg.MaxFieldCount)
	}

	// Unknown tenant should still get default
	cfg2 := s.Get("other-tenant")
	if cfg2.DepthLimit != 10 {
		t.Errorf("expected DepthLimit=10 from default, got %d", cfg2.DepthLimit)
	}
}

func TestDelete(t *testing.T) {
	s := New(&rules.Config{DepthLimit: 5})
	s.Set("tenant-beta", &rules.Config{DepthLimit: 1})

	s.Delete("tenant-beta")
	cfg := s.Get("tenant-beta")
	if cfg.DepthLimit != 5 {
		t.Errorf("expected fallback to default DepthLimit=5, got %d", cfg.DepthLimit)
	}
}

func TestList(t *testing.T) {
	s := New(nil)
	s.Set("a", &rules.Config{})
	s.Set("b", &rules.Config{})

	ids := s.List()
	if len(ids) != 2 {
		t.Errorf("expected 2 tenants, got %d: %v", len(ids), ids)
	}
}

func TestCount(t *testing.T) {
	s := New(nil)
	if s.Count() != 0 {
		t.Errorf("expected 0, got %d", s.Count())
	}
	s.Set("t1", &rules.Config{})
	if s.Count() != 1 {
		t.Errorf("expected 1, got %d", s.Count())
	}
}

func TestExtractTenantID(t *testing.T) {
	tests := []struct {
		key      string
		expected string
	}{
		{"acme_a1b2c3", "acme"},
		{"mytenant_secret", "mytenant"},
		{"simplekey", "simplekey"},
		{"", ""},
		// Multi-underscore: uses LAST underscore as separator
		{"my_tenant_secret123", "my_tenant"},
		{"a_b_c_d", "a_b_c"},
	}
	for _, tt := range tests {
		got := ExtractTenantID(tt.key)
		if got != tt.expected {
			t.Errorf("ExtractTenantID(%q) = %q, want %q", tt.key, got, tt.expected)
		}
	}
}

func TestValidateKey_Valid(t *testing.T) {
	ks := NewKeyStore(map[string]string{
		"acme":      "secret123",
		"my_tenant": "mysupersecret",
	})

	tid, ok := ks.Validate("acme_secret123")
	if !ok {
		t.Fatal("expected valid key for acme")
	}
	if tid != "acme" {
		t.Errorf("expected tenantID=acme, got %q", tid)
	}

	tid, ok = ks.Validate("my_tenant_mysupersecret")
	if !ok {
		t.Fatal("expected valid key for my_tenant")
	}
	if tid != "my_tenant" {
		t.Errorf("expected tenantID=my_tenant, got %q", tid)
	}
}

func TestValidateKey_WrongSecret(t *testing.T) {
	ks := NewKeyStore(map[string]string{
		"acme": "correct_secret",
	})

	tid, ok := ks.Validate("acme_wrong_secret")
	if ok {
		t.Fatal("expected invalid key for wrong secret")
	}
	if tid != "" {
		t.Errorf("expected empty tenantID, got %q", tid)
	}
}

func TestValidateKey_UnknownTenant(t *testing.T) {
	ks := NewKeyStore(map[string]string{
		"known": "secret",
	})

	tid, ok := ks.Validate("unknown_secret")
	if ok {
		t.Fatal("expected invalid key for unknown tenant")
	}
	if tid != "" {
		t.Errorf("expected empty tenantID, got %q", tid)
	}
}

func TestValidateKey_EmptyKey(t *testing.T) {
	ks := NewKeyStore(map[string]string{
		"test": "secret",
	})

	tid, ok := ks.Validate("")
	if ok {
		t.Fatal("expected invalid key for empty string")
	}
	if tid != "" {
		t.Errorf("expected empty tenantID, got %q", tid)
	}

	// Also test no-underscore key (no secret component)
	tid, ok = ks.Validate("justtenant")
	if ok {
		t.Fatal("expected invalid key when no secret component")
	}
	if tid != "" {
		t.Errorf("expected empty tenantID, got %q", tid)
	}
}
