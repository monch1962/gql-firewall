package rules

import (
	"testing"
)

func TestValidate_AcceptNormalConfig(t *testing.T) {
	cfg := &Config{DepthLimit: 10, MaxFieldCount: 100}
	if err := Validate(cfg); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestValidate_AcceptFieldBlocklistOnly(t *testing.T) {
	cfg := &Config{FieldBlocklist: []string{"__schema"}}
	if err := Validate(cfg); err != nil {
		t.Errorf("expected no error for blocklist-only config, got %v", err)
	}
}

func TestValidate_AcceptAllowedOpsOnly(t *testing.T) {
	cfg := &Config{AllowedOperations: []string{"query"}}
	if err := Validate(cfg); err != nil {
		t.Errorf("expected no error for allowed_operations-only config, got %v", err)
	}
}

func TestValidate_RejectEmptyConfig(t *testing.T) {
	cfg := &Config{}
	if err := Validate(cfg); err != ErrNoProtection {
		t.Errorf("expected ErrNoProtection, got %v", err)
	}
}

func TestValidate_RejectNilConfig(t *testing.T) {
	if err := Validate(nil); err != ErrNilConfig {
		t.Errorf("expected ErrNilConfig, got %v", err)
	}
}

func TestValidate_RejectNegativeDepth(t *testing.T) {
	cfg := &Config{DepthLimit: -1, FieldBlocklist: []string{"__schema"}}
	if err := Validate(cfg); err != ErrNegativeDepth {
		t.Errorf("expected ErrNegativeDepth, got %v", err)
	}
}

func TestValidate_RejectNegativeFieldCount(t *testing.T) {
	cfg := &Config{MaxFieldCount: -5, FieldBlocklist: []string{"__schema"}}
	if err := Validate(cfg); err != ErrNegativeFields {
		t.Errorf("expected ErrNegativeFields, got %v", err)
	}
}

func TestValidate_BlockedOpIsProtection(t *testing.T) {
	cfg := &Config{BlockedOperations: []string{"subscription"}}
	if err := Validate(cfg); err != nil {
		t.Errorf("expected no error for blocked_operations config, got %v", err)
	}
}
