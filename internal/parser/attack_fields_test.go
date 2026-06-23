package parser

import (
	"testing"
)

func TestParseQuery_DirectivesCounted(t *testing.T) {
	info, err := Parse("{ hello @skip(if: true) @include(if: true) }")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Directives != 2 {
		t.Errorf("expected 2 directives, got %d", info.Directives)
	}
}

func TestParseQuery_BatchSizeMultiOp(t *testing.T) {
	info, err := Parse("query Q1 { hello } query Q2 { world }")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.BatchSize != 2 {
		t.Errorf("expected batch_size=2, got %d", info.BatchSize)
	}
}

func TestParseQuery_BatchSizeSingleOp(t *testing.T) {
	info, err := Parse("{ hello }")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.BatchSize != 1 {
		t.Errorf("expected batch_size=1, got %d", info.BatchSize)
	}
}

func TestParseQuery_ArgumentDepthMeasured(t *testing.T) {
	info, err := Parse(`{ user(filter: {age: {gt: 18}, name: {eq: "Alice"}}) { name } }`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ArgumentDepth < 2 {
		t.Errorf("expected argument_depth >= 2 for nested args, got %d", info.ArgumentDepth)
	}
}

func TestParseQuery_FlatArgumentDepth(t *testing.T) {
	info, err := Parse(`{ user(id: 42) { name } }`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ArgumentDepth != 1 {
		t.Errorf("expected argument_depth=1 for flat arg, got %d", info.ArgumentDepth)
	}
}

func TestParseQuery_ListsRequestedPluralFields(t *testing.T) {
	info, err := Parse("{ users { name } posts { title } }")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ListsRequested < 2 {
		t.Errorf("expected lists_requested >= 2 for 'users' and 'posts', got %d", info.ListsRequested)
	}
}

func TestParseQuery_FragmentSpreadsCounted(t *testing.T) {
	info, err := Parse(`{ ...A } fragment A on Query { ...B } fragment B on Query { name }`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.FragmentSpreadCount < 2 {
		t.Errorf("expected fragment_spread_count >= 2, got %d", info.FragmentSpreadCount)
	}
}

func TestParseQuery_QueryHashGenerated(t *testing.T) {
	info, err := Parse("{ hello }")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.QueryHash == "" {
		t.Error("expected non-empty query_hash")
	}
	if len(info.QueryHash) != 16 {
		t.Errorf("expected query_hash length 16 (8 bytes hex), got %d: %s", len(info.QueryHash), info.QueryHash)
	}
}

func TestParseQuery_HashConsistent(t *testing.T) {
	info1, _ := Parse("{ hello }")
	info2, _ := Parse("{ hello }")
	if info1.QueryHash != info2.QueryHash {
		t.Errorf("expected identical hashes for identical queries: %s vs %s", info1.QueryHash, info2.QueryHash)
	}
}

func TestParseQuery_AllFieldsPopulated(t *testing.T) {
	info, err := Parse(`query GetUsers { 
		users @skip(if: false) { 
			name 
			posts(filter: {published: true}) { title } 
		} 
	}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.OperationType != "query" {
		t.Errorf("expected operation_type=query, got %s", info.OperationType)
	}
	if info.OperationName != "GetUsers" {
		t.Errorf("expected operation_name=GetUsers, got %s", info.OperationName)
	}
	if info.Depth < 2 {
		t.Errorf("expected depth >= 2, got %d", info.Depth)
	}
	if info.FieldCount < 3 {
		t.Errorf("expected field_count >= 3, got %d", info.FieldCount)
	}
	if info.Directives < 1 {
		t.Errorf("expected directives >= 1, got %d", info.Directives)
	}
	if info.BatchSize != 1 {
		t.Errorf("expected batch_size=1, got %d", info.BatchSize)
	}
	if info.ArgumentDepth < 1 {
		t.Errorf("expected argument_depth >= 1, got %d", info.ArgumentDepth)
	}
	if info.ListsRequested < 1 {
		t.Errorf("expected lists_requested >= 1, got %d", info.ListsRequested)
	}
	if info.FragmentSpreadCount != 0 {
		t.Errorf("expected fragment_spread_count=0, got %d", info.FragmentSpreadCount)
	}
	if info.QueryHash == "" {
		t.Error("expected non-empty query_hash")
	}
}
