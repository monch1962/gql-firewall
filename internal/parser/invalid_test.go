package parser

import (
	"testing"
)

func TestParseQuery_WhitespaceOnly(t *testing.T) {
	_, err := Parse("   ")
	if err == nil {
		t.Fatal("expected error for whitespace-only query, got nil")
	}
}

func TestParseQuery_CommentOnly(t *testing.T) {
	_, err := Parse("# this is just a comment")
	if err == nil {
		t.Fatal("expected error for comment-only query, got nil")
	}
}

func TestParseQuery_OperationWithoutSelection(t *testing.T) {
	_, err := Parse("query")
	if err == nil {
		t.Fatal("expected error for operation with no selection set, got nil")
	}
}

func TestParseQuery_InvalidOperationKeyword(t *testing.T) {
	_, err := Parse("mutationz { hello }")
	if err == nil {
		t.Fatal("expected error for invalid operation keyword, got nil")
	}
}

func TestParseQuery_MultipleUnnamedOperations(t *testing.T) {
	_, err := Parse("query { a } query { b }")
	if err == nil {
		t.Fatal("expected error for multiple unnamed operations, got nil")
	}
}

func TestParseQuery_CircularFragment(t *testing.T) {
	q := `query { ...A } fragment A on Query { ...B } fragment B on Query { ...A }`
	// gqlparser accepts circular fragments at parse time; visited set prevents
	// infinite recursion/stack overflow. Should not crash.
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = info // Successful parse without crash = pass
}

func TestParseQuery_NullByteInField(t *testing.T) {
	q := "{ hell\x00o }"
	_, err := Parse(q)
	if err == nil {
		t.Fatal("expected error for null byte in field name, got nil")
	}
}

func TestParseQuery_VeryLongFieldChain(t *testing.T) {
	// Build a deeply nested but valid chain
	q := "{ a"
	for i := 0; i < 100; i++ {
		q += " { b"
	}
	for i := 0; i < 100; i++ {
		q += " }"
	}
	q += " }"
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error for deep valid query: %v", err)
	}
	if info.Depth != 101 {
		t.Errorf("expected depth 101, got %d", info.Depth)
	}
}

func TestParseQuery_UnicodeCharacters(t *testing.T) {
	q := "{ \u00e9\u00e0\u00fc }" // éàü in field name
	_, err := Parse(q)
	if err == nil {
		t.Fatal("expected error for unicode field name, got nil")
	}
}

func TestParseQuery_ValidDirective(t *testing.T) {
	q := `query @deprecated { hello }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error for query with directive: %v", err)
	}
	if info.OperationType != "query" {
		t.Errorf("expected query, got %q", info.OperationType)
	}
}

func TestParseQuery_EmptySelectionSet(t *testing.T) {
	q := "{ }"
	_, err := Parse(q)
	if err == nil {
		t.Fatal("expected error for empty selection set, got nil")
	}
}

func TestParseQuery_ControlCharacters(t *testing.T) {
	// Tab character between tokens is valid whitespace in GraphQL.
	// Instead, test a backtick which is not valid in a field name.
	q := "{ hel`lo }"
	_, err := Parse(q)
	if err == nil {
		t.Fatal("expected error for backtick character in field name, got nil")
	}
}
