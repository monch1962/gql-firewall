package parser

import (
	"errors"
	"strings"
	"testing"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/lexer"
)

// ── R102: value-node budget — string literals are AST nodes too ────────────
// R101 bounded the AST by counting name and number tokens. It skipped string
// and block-string literals on the reasoning that their *content* allocates
// nothing (Raw is a slice of the input). That is true of the bytes, but not of
// the node: every string literal materialises an ast.Value, and a list of short
// literals therefore costs ~4 bytes of payload per ~100 bytes of AST.
//
// Measured on this tree before the fix: `{a(x:["s" "s" …])}` with 100,000
// literals is a 390KB body that the scan reported as 2 nodes (just `a` and
// `x`). It parsed successfully and allocated 24.5MB. The int-valued control of
// the same node count is capped at 10,000 tokens and allocates 2.3MB — so the
// budget's ceiling was exceeded by 10.7x, and at the 1MB body limit one parse
// reaches ~63MB (64 pool slots → ~4GB, OOM).
//
// CAPEC-130: Excessive Allocation.

// stringValueBomb builds `{a(x:["s" "s" …])}` with n literals under one field.
func stringValueBomb(n int) string {
	var b strings.Builder
	b.Grow(n*5 + 16)
	b.WriteString(`{a(x:[`)
	for i := 0; i < n; i++ {
		b.WriteString(`"s" `)
	}
	b.WriteString(`])}`)
	return b.String()
}

// blockStringValueBomb is the block-string spelling of the same bomb.
func blockStringValueBomb(n int) string {
	var b strings.Builder
	b.Grow(n*9 + 16)
	b.WriteString(`{a(x:[`)
	for i := 0; i < n; i++ {
		b.WriteString(`"""b""" `)
	}
	b.WriteString(`])}`)
	return b.String()
}

// CAPEC-130: a list of short string literals is a value-node bomb. Every
// literal becomes an AST Value, so the budget must count each one.
func TestAttack_StringValueBombRejected(t *testing.T) {
	q := stringValueBomb(MaxQueryNodes + 1)
	if _, err := Parse(q); !errors.Is(err, ErrQueryTooLarge) {
		t.Fatalf("expected ErrQueryTooLarge for %d string values, got %v", MaxQueryNodes+1, err)
	}
}

// CAPEC-130: block strings are the same node kind under a different lexer path.
func TestAttack_BlockStringValueBombRejected(t *testing.T) {
	q := blockStringValueBomb(MaxQueryNodes + 1)
	if _, err := Parse(q); !errors.Is(err, ErrQueryTooLarge) {
		t.Fatalf("expected ErrQueryTooLarge for %d block strings, got %v", MaxQueryNodes+1, err)
	}
}

// CAPEC-130: the bound must be exact — a document at the limit parses, the next
// literal is rejected, so the fix cannot silently halve the useful budget.
func TestAttack_StringValueBudgetBoundIsExact(t *testing.T) {
	// `{a(x:[…])}` consumes 2 name tokens (a, x); the rest is literals.
	atLimit := stringValueBomb(MaxQueryNodes - 2)
	if _, err := Parse(atLimit); err != nil {
		t.Fatalf("exactly %d nodes should be allowed: %v", MaxQueryNodes, err)
	}
	if _, err := Parse(stringValueBomb(MaxQueryNodes - 1)); !errors.Is(err, ErrQueryTooLarge) {
		t.Fatalf("expected rejection one literal past the bound, got %v", err)
	}
}

// CAPEC-130: the mirror image — one large string argument is a single node. The
// budget must not count bytes inside a literal, or legitimate large arguments
// become a denial of service.
func TestAttack_OneLargeStringArgumentStillAdmitted(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{a(s:"`)
	for b.Len() < 500_000 {
		b.WriteString("fieldName ")
	}
	b.WriteString(`")}`)
	if _, err := Parse(b.String()); err != nil {
		t.Fatalf("a single large string argument must be admitted: %v", err)
	}
}

// CAPEC-130: undercount is the bypass, so the scan must never report fewer node
// tokens than the lexer emits once literals are counted as nodes. Over-counting
// is only a false rejection, and is covered by the mirror test above.
func TestAttack_StringNodeCountNeverUndercountsLexer(t *testing.T) {
	corpus := []string{
		`{a(s:"x")}`, `{a(x:["s" "s" "s"])}`, `{a(x:{k:"s" j:"t"})}`,
		`{a(x:["""b""" """c"""])}`, `{a(x:"\u0022 s")}`,
		`{a b} # "s" "s"` + "\n" + `{c}`,
		`{a(x:["s" 1 E "t"])}`,
		stringValueBomb(100), blockStringValueBomb(100),
	}
	for _, q := range corpus {
		lexNodes := 0
		l := lexer.New(&ast.Source{Input: q, Name: "t"})
		for {
			tok, err := l.ReadToken()
			if err != nil || tok.Kind == lexer.EOF {
				break
			}
			switch tok.Kind {
			case lexer.Name, lexer.Int, lexer.Float, lexer.String, lexer.BlockString:
				lexNodes++
			}
		}
		if got := countQueryNodes(q); got < lexNodes {
			t.Errorf("%q: scanner counted %d nodes, lexer produced %d — undercount is a budget bypass", q, got, lexNodes)
		}
	}
}

// CAPEC-130: a batch item gets its own document budget, but the body limit is
// the only bound on how many items fit. At the default 1MB body a batch of
// string bombs must still be rejected per item rather than parsed.
func TestAttack_StringValueBombRejectedNotParsed(t *testing.T) {
	if _, err := Parse(stringValueBomb(MaxQueryNodes * 4)); !errors.Is(err, ErrQueryTooLarge) {
		t.Fatalf("expected rejection, got %v", err)
	}
}
