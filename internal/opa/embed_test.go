package opa

import (
	"testing"

	"github.com/monch1962/gql-firewall/internal/parser"
)

const testPolicy = `package graphql

default allow := false

allow if {
	count(deny) == 0
}

deny contains msg if {
	input.depth > input.params.depth_limit
	msg := sprintf("query depth %d exceeds limit %d", [input.depth, input.params.depth_limit])
}

deny contains msg if {
	input.tenant_config
	input.depth > input.tenant_config.depth_limit
	msg := sprintf("tenant depth limit exceeded for %s", [input.tenant_id])
}
`

func TestEmbedded_AllowsValidQuery(t *testing.T) {
	store := NewDataStore()
	store.SetParams(map[string]interface{}{"depth_limit": 10})

	e, err := NewEmbedded(EmbedConfig{Policy: testPolicy, Store: store})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	input := BuildInput(&parser.QueryInfo{OperationType: "query", Depth: 5, FieldCount: 3}, store)
	result, err := e.Evaluate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed, got blocked: %s", result.Reason)
	}
}

func TestEmbedded_BlocksDeepQuery(t *testing.T) {
	store := NewDataStore()
	store.SetParams(map[string]interface{}{"depth_limit": 5})

	e, err := NewEmbedded(EmbedConfig{Policy: testPolicy, Store: store})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	input := BuildInput(&parser.QueryInfo{OperationType: "query", Depth: 20, FieldCount: 3}, store)
	result, err := e.Evaluate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Fatal("expected blocked, got allowed")
	}
	if result.Reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestEmbedded_Configured(t *testing.T) {
	store := NewDataStore()
	store.SetParams(map[string]interface{}{"depth_limit": 10})

	e, err := NewEmbedded(EmbedConfig{Policy: testPolicy, Store: store})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !e.Configured() {
		t.Error("expected Configured()=true for embedded evaluator")
	}
}

func TestEmbedded_EmptyPolicy(t *testing.T) {
	_, err := NewEmbedded(EmbedConfig{Policy: ""})
	if err == nil {
		t.Fatal("expected error for empty policy, got nil")
	}
}

func TestEmbedded_TenantOverride(t *testing.T) {
	store := NewDataStore()
	store.SetParams(map[string]interface{}{"depth_limit": 10})
	store.SetTenant("strict", map[string]interface{}{"depth_limit": 3})

	e, err := NewEmbedded(EmbedConfig{Policy: testPolicy, Store: store})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Tenant with strict limit should be blocked at depth 5
	input := BuildInput(&parser.QueryInfo{OperationType: "query", Depth: 5, TenantID: "strict"}, store)
	result, err := e.Evaluate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Fatal("expected blocked for strict tenant")
	}

	// Non-tenant should use global params (depth 5 < 10)
	input2 := BuildInput(&parser.QueryInfo{OperationType: "query", Depth: 5}, store)
	result2, err := e.Evaluate(input2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result2.Allowed {
		t.Errorf("expected allowed for non-tenant, got blocked: %s", result2.Reason)
	}
}
