package opa

import (
	"testing"
)

func TestNewDataStore(t *testing.T) {
	s := NewDataStore()
	if s == nil {
		t.Fatal("expected non-nil store")
	}
	if c := s.CountTenants(); c != 0 {
		t.Errorf("expected 0 tenants, got %d", c)
	}
}

func TestSetAndGetParams(t *testing.T) {
	s := NewDataStore()
	s.SetParams(map[string]interface{}{
		"depth_limit": 10,
		"max_field_count": 100,
	})
	params := s.GetParams()
	if params["depth_limit"] != 10 {
		t.Errorf("expected depth_limit=10, got %v", params["depth_limit"])
	}
	if params["max_field_count"] != 100 {
		t.Errorf("expected max_field_count=100, got %v", params["max_field_count"])
	}
}

func TestSetParams_ReplaceAll(t *testing.T) {
	s := NewDataStore()
	s.SetParams(map[string]interface{}{"depth_limit": 10})
	s.SetParams(map[string]interface{}{"max_field_count": 50})
	params := s.GetParams()
	if _, ok := params["depth_limit"]; ok {
		t.Errorf("expected depth_limit to be removed after replacement")
	}
	if params["max_field_count"] != 50 {
		t.Errorf("expected max_field_count=50, got %v", params["max_field_count"])
	}
}

func TestTenantCRUD(t *testing.T) {
	s := NewDataStore()
	s.SetTenant("acme", map[string]interface{}{"depth_limit": 5})
	s.SetTenant("corp", map[string]interface{}{"depth_limit": 3})

	if c := s.CountTenants(); c != 2 {
		t.Errorf("expected 2 tenants, got %d", c)
	}

	ids := s.ListTenants()
	if len(ids) != 2 {
		t.Errorf("expected 2 tenant IDs, got %d", len(ids))
	}

	cfg := s.GetTenant("acme")
	if cfg == nil {
		t.Fatal("expected tenant config")
	}
	if cfg["depth_limit"] != 5 {
		t.Errorf("expected depth_limit=5, got %v", cfg["depth_limit"])
	}

	s.DeleteTenant("acme")
	if c := s.CountTenants(); c != 1 {
		t.Errorf("expected 1 tenant after delete, got %d", c)
	}

	cfg = s.GetTenant("acme")
	if cfg != nil {
		t.Errorf("expected nil after delete, got %v", cfg)
	}
}

func TestGetTenant_Unknown(t *testing.T) {
	s := NewDataStore()
	cfg := s.GetTenant("nonexistent")
	if cfg != nil {
		t.Errorf("expected nil for unknown tenant, got %v", cfg)
	}
}

func TestLoadParamsFromJSON(t *testing.T) {
	s := NewDataStore()
	data := []byte(`{"depth_limit": 10, "max_field_count": 50}`)
	if err := s.LoadParamsFromJSON(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	params := s.GetParams()
	if params["depth_limit"].(float64) != 10 {
		t.Errorf("expected depth_limit=10, got %v (%T)", params["depth_limit"], params["depth_limit"])
	}
}

func TestLoadParamsFromJSON_Invalid(t *testing.T) {
	s := NewDataStore()
	data := []byte(`{bad json}`)
	if err := s.LoadParamsFromJSON(data); err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}
