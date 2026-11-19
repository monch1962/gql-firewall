package parser

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/lexer"
)

// ── R101: AST amplification — bounding nesting does not bound memory ────────
// R98 capped brace/bracket nesting, so a payload can no longer blow the stack.
// It can still blow the heap: gqlparser allocates a node per field/value, so a
// flat document costs ~282 bytes of allocation per byte of payload.
//
// Measured on this tree before the fix: a 1MB body of `{a a a …}` is 524,287
// field nodes, 147.7MB allocated, 123.6MB of heap retained, 177ms of CPU — at
// depth 1, so every depth/cost rule passes it. The parse pool is 64 slots, so
// 64 concurrent requests reach ~7.9GB and the sidecar is OOM-killed.
//
// The body limit cannot help: it bounds the *input*, not the expansion. The
// budget has to be counted in the same linear pre-parse scan as the nesting
// check, before the recursive descent allocates anything.
//
// CAPEC-130: Excessive Allocation.

// flatSelection builds `{a a a … }` with `n` field tokens — valid syntax,
// depth 1, zero nesting.
func flatSelection(n int) string {
	var b strings.Builder
	b.Grow(n*2 + 2)
	b.WriteString("{")
	for i := 0; i < n; i++ {
		b.WriteString("a ")
	}
	b.WriteString("}")
	return b.String()
}

// aliasBomb builds `{x0:a x1:a …}` — two name tokens per field, one AST node
// per alias plus one per field.
func aliasBomb(n int) string {
	var b strings.Builder
	b.Grow(n*6 + 2)
	b.WriteString("{")
	for i := 0; i < n; i++ {
		b.WriteString("x")
		b.WriteString(itoa(i))
		b.WriteString(":a ")
	}
	b.WriteString("}")
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// valueBomb builds `{a(x:[1 2 3 … ])}` — list values are AST nodes too, so a
// budget that only counts field names would let this through.
func valueBomb(n int) string {
	var b strings.Builder
	b.Grow(n*2 + 16)
	b.WriteString("{a(x:[")
	for i := 0; i < n; i++ {
		b.WriteString("1 ")
	}
	b.WriteString("])}")
	return b.String()
}

func TestAttack_WideFlatSelectionBombRejected(t *testing.T) {
	q := flatSelection(120000) // ~240KB: a fifth of the default body limit

	start := time.Now()
	info, err := Parse(q)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected the flat selection bomb to be rejected, parsed %d fields", info.FieldCount)
	}
	if !errors.Is(err, ErrQueryTooLarge) {
		t.Fatalf("expected ErrQueryTooLarge sentinel, got %v", err)
	}
	if info != nil {
		t.Errorf("expected nil QueryInfo on rejection, got %+v", info)
	}
	// Rejection must happen in the linear scan, not after the parser has
	// already allocated the tree: parse alone took ~80ms for this payload.
	if elapsed > 50*time.Millisecond {
		t.Errorf("rejection took %s — the budget was not enforced before parsing", elapsed)
	}
}

func TestAttack_WideAliasBombRejected(t *testing.T) {
	// Aliases double the node count per field and defeat any rule that
	// de-duplicates field names before measuring.
	if _, err := Parse(aliasBomb(30000)); !errors.Is(err, ErrQueryTooLarge) {
		t.Fatalf("expected alias bomb to be rejected, got %v", err)
	}
}

func TestAttack_ValueListBombRejected(t *testing.T) {
	// Argument values allocate nodes just as selections do.
	if _, err := Parse(valueBomb(60000)); !errors.Is(err, ErrQueryTooLarge) {
		t.Fatalf("expected value-list bomb to be rejected, got %v", err)
	}
}

// CAPEC-130: the mirror-image failure — a budget that counts inert text is a
// denial of service against legitimate traffic. Name-like bytes inside a string
// literal never become AST nodes, so they must not consume the budget.
func TestAttack_NodeBudgetIgnoresInertText(t *testing.T) {
	var inner strings.Builder
	for inner.Len() < 400_000 {
		inner.WriteString("fieldName ")
	}
	q := `{a(s: "` + inner.String() + `")}
# ` + inner.String() + "\n"

	info, err := Parse(q)
	if err != nil {
		t.Fatalf("legitimate large string/comment payload wrongly rejected: %v", err)
	}
	if info.FieldCount != 1 {
		t.Errorf("expected 1 field, got %d", info.FieldCount)
	}
}

func TestAttack_NodeBudgetBoundIsExact(t *testing.T) {
	// Admit everything up to the documented bound; reject the next token.
	// flatSelection(n) is n field names plus one selection set, and R103
	// charges the container, so n-1 fields sit exactly on the bound.
	atLimit := flatSelection(MaxQueryNodes - 1)
	if _, err := Parse(atLimit); err != nil {
		t.Fatalf("exactly %d nodes should be allowed: %v", MaxQueryNodes, err)
	}
	if _, err := Parse(flatSelection(MaxQueryNodes)); !errors.Is(err, ErrQueryTooLarge) {
		t.Fatalf("expected rejection at %d nodes, got %v", MaxQueryNodes+1, err)
	}
}

// CAPEC-130: an undercount is a bypass, so the scan must never report fewer
// node tokens than the real lexer produces. Over-counting is only an
// availability question, covered by the inert-text test above.
func TestAttack_NodeCountNeverUndercountsLexer(t *testing.T) {
	corpus := []string{
		"{a}", "{a b c}", "{x0:a x1:a}", "{a(x:[1 2 3])}",
		`{a(s:"ns ns ns")}`, "\"\"\"block name name\"\"\"", "# comment name\n{a}",
		"{...F} fragment F on T {a b}", "{a(x:{k:1 j:2})}", "{$v}",
		"{a(x:-1e10 y:2.5)}", "{a b} # tail\n{c}",
		"{a(" + strings.Repeat("1 ", 500) + ")}",
		flatSelection(1000),
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
			case lexer.Name, lexer.Int, lexer.Float:
				lexNodes++
			}
		}
		if got := countQueryNodes(q); got < lexNodes {
			t.Errorf("%q: scanner counted %d node tokens, lexer produced %d — undercount is a budget bypass", q, got, lexNodes)
		}
	}
}
