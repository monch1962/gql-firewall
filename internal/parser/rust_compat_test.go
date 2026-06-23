package parser

import (
	"testing"
)

// These tests mirror the exact scenarios the Rust gql-parser sidecar tested.
// They ensure no coverage is lost when removing the Rust code.

func TestGoParser_RustCompat_SimpleQuery(t *testing.T) {
	// Rust: test_simple — { hello } → depth=1, field_count=1
	info, err := Parse("{ hello }")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Depth != 1 {
		t.Errorf("expected depth=1, got %d", info.Depth)
	}
	if info.FieldCount != 1 {
		t.Errorf("expected field_count=1, got %d", info.FieldCount)
	}
}

func TestGoParser_RustCompat_NestedQuery(t *testing.T) {
	// Rust: test_nested — { a { b } } → depth=2, field_count=2
	info, err := Parse("{ a { b } }")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Depth != 2 {
		t.Errorf("expected depth=2, got %d", info.Depth)
	}
	if info.FieldCount != 2 {
		t.Errorf("expected field_count=2, got %d", info.FieldCount)
	}
}

func TestGoParser_RustCompat_DeepQuery(t *testing.T) {
	// Rust: test_deep — { a { b { c { d } } } } → depth=4, field_count=4
	info, err := Parse("{ a { b { c { d } } } }")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Depth != 4 {
		t.Errorf("expected depth=4, got %d", info.Depth)
	}
	if info.FieldCount != 4 {
		t.Errorf("expected field_count=4, got %d", info.FieldCount)
	}
}

func TestGoParser_RustCompat_MutationType(t *testing.T) {
	// Rust: test_mutation — mutation M { create { id } } → operation_type=mutation
	info, err := Parse("mutation M { create { id } }")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.OperationType != "mutation" {
		t.Errorf("expected operation_type=mutation, got %q", info.OperationType)
	}
}

func TestGoParser_RustCompat_NamedOperation(t *testing.T) {
	// Rust: test_named — query Q { x } → operation_name=Some("Q")
	info, err := Parse("query Q { x }")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.OperationName != "Q" {
		t.Errorf("expected operation_name=Q, got %q", info.OperationName)
	}
}

func TestGoParser_RustCompat_FieldPaths(t *testing.T) {
	// Rust: test_paths — { u { p { e } } } → field_paths contains "u.p.e"
	info, err := Parse("{ u { p { e } } }")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, p := range info.FieldPaths {
		if p == "u.p.e" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected field_paths to contain %q, got %v", "u.p.e", info.FieldPaths)
	}
}

func TestGoParser_RustCompat_InvalidQueryReturnsError(t *testing.T) {
	// Rust: test_invalid — both bad syntax and empty string should error
	_, err := Parse("{ bad !!! }")
	if err == nil {
		t.Error("expected error for malformed query, got nil")
	}
	_, err = Parse("")
	if err == nil {
		t.Error("expected error for empty query, got nil")
	}
}

func TestGoParser_RustCompat_CircularFragmentNoCrash(t *testing.T) {
	// Rust: test_circular_fragment_no_crash — circular fragment should not crash
	q := "query { ...A } fragment A on Query { ...B } fragment B on Query { ...A }"
	_, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error for circular fragment: %v", err)
	}
	// Just verifying no panic/crash
}
