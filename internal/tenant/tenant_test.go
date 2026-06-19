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
	}
	for _, tt := range tests {
		got := ExtractTenantID(tt.key)
		if got != tt.expected {
			t.Errorf("ExtractTenantID(%q) = %q, want %q", tt.key, got, tt.expected)
		}
	}
}
