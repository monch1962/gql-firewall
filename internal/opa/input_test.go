package opa

import (
	"encoding/json"
	"testing"

	"github.com/monch1962/gql-firewall/internal/parser"
)

func TestBuildInput(t *testing.T) {
	info := &parser.QueryInfo{
		OperationType:       "query",
		OperationName:       "GetUser",
		Depth:               3,
		FieldCount:          10,
		FieldPaths:          []string{"user", "user.name"},
		TenantID:            "acme",
		Directives:          2,
		BatchSize:           1,
		ArgumentDepth:       3,
		ListsRequested:      1,
		FragmentSpreadCount: 0,
		QueryHash:           "a1b2c3d4",
	}
	store := NewDataStore()
	store.SetParams(map[string]interface{}{"depth_limit": 10})
	input := BuildInput(info, store)
	if input.OperationType != "query" {
		t.Errorf("expected operation_type=query, got %s", input.OperationType)
	}
	if input.OperationName != "GetUser" {
		t.Errorf("expected operation_name=GetUser, got %s", input.OperationName)
	}
	if input.Depth != 3 {
		t.Errorf("expected depth=3, got %d", input.Depth)
	}
	if input.TenantID != "acme" {
		t.Errorf("expected tenant_id=acme, got %s", input.TenantID)
	}
	if input.Params == nil {
		t.Fatal("expected params to be populated")
	}
	if input.Params["depth_limit"] != 10 {
		t.Errorf("expected depth_limit=10, got %v", input.Params["depth_limit"])
	}
}

func TestBuildInput_EmptyInfo(t *testing.T) {
	info := &parser.QueryInfo{}
	input := BuildInput(info, NewDataStore())
	if input == nil {
		t.Fatal("expected non-nil input")
	}
}

func TestInput_JSONSerialization(t *testing.T) {
	input := &Input{
		OperationType: "query",
		Depth:         5,
		FieldCount:    20,
		FieldPaths:    []string{"user"},
		TenantID:      "test",
	}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var decoded Input
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if decoded.Depth != 5 {
		t.Errorf("expected depth=5, got %d", decoded.Depth)
	}
}
