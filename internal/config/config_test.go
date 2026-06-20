package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	content := `{
		"depth_limit": 5,
		"max_field_count": 50,
		"blocked_operations": ["mutation"],
		"field_allowlist": ["user.name", "user.email"]
	}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DepthLimit != 5 {
		t.Errorf("expected DepthLimit=5, got %d", cfg.DepthLimit)
	}
	if cfg.MaxFieldCount != 50 {
		t.Errorf("expected MaxFieldCount=50, got %d", cfg.MaxFieldCount)
	}
	if len(cfg.BlockedOperations) != 1 || cfg.BlockedOperations[0] != "mutation" {
		t.Errorf("expected BlockedOperations=[\"mutation\"], got %v", cfg.BlockedOperations)
	}
}

func TestLoadConfig_MinimalFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	content := `{}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DepthLimit != 0 {
		t.Errorf("expected DepthLimit=0 (default), got %d", cfg.DepthLimit)
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/rules.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	content := `{bad json}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestLoadConfig_AllFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	content := `{
		"depth_limit": 10,
		"max_field_count": 100,
		"blocked_operations": ["mutation", "subscription"],
		"allowed_operations": ["query"],
		"field_allowlist": ["public.*"],
		"field_blocklist": ["admin.*", "secrets.*"]
	}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DepthLimit != 10 {
		t.Errorf("expected DepthLimit=10, got %d", cfg.DepthLimit)
	}
	if cfg.MaxFieldCount != 100 {
		t.Errorf("expected MaxFieldCount=100, got %d", cfg.MaxFieldCount)
	}
	if len(cfg.AllowedOperations) != 1 || cfg.AllowedOperations[0] != "query" {
		t.Errorf("expected AllowedOperations=[\"query\"], got %v", cfg.AllowedOperations)
	}
	if len(cfg.FieldBlocklist) != 2 {
		t.Errorf("expected 2 blocked fields, got %d", len(cfg.FieldBlocklist))
	}
}

func TestLoadConfig_EmptyPath(t *testing.T) {
	_, err := Load("")
	if err == nil {
		t.Fatal("expected error for empty path, got nil")
	}
}

