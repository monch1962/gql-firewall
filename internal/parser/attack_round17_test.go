package parser

import (
	"errors"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// ── R103: the budget must charge container tokens, not just leaves ─────────
// R101 counted name and number tokens; R102 added string/block-string literals.
// Both left `{` and `[` uncounted, on the reasoning that they only open a
// selection set or value container and the leaves inside carry the cost. That
// is false for an *empty* container: `[]` and `{}` are valid GraphQL values,
// each materialises an ast.ListValue / ast.ObjectValue, and the scan charges
// nothing at all.
//
// Measured on this tree before the fix:
//   - `{a(x:[[] [] …])}` with 100,000 empty lists is a 300KB body that the scan
//     reported as 2 nodes (just `a` and `x`). It parsed successfully and
//     allocated 31.3MB — 11x the ~2.8MB ceiling the 10,000-node budget implies.
//   - the `{}` spelling, 50,000 values in 150KB, allocated 15.6MB for the same
//     2 counted nodes.
//
// That is 3 bytes of payload per AST node — cheaper than R102's string-literal
// bomb (4 bytes) — so at the 1MB body limit one parse reaches ~100MB and a full
// 64-slot parse pool reaches ~6GB: OOM. Every token kind that materialises a
// node must be charged; a container is a node.
//
// CAPEC-130: Excessive Allocation.

// emptyListValueBomb builds `{a(x:[[] [] …])}` with n empty list values.
func emptyListValueBomb(n int) string {
	var b strings.Builder
	b.Grow(n*3 + 16)
	b.WriteString(`{a(x:[`)
	for i := 0; i < n; i++ {
		b.WriteString(`[] `)
	}
	b.WriteString(`])}`)
	return b.String()
}

// emptyObjectValueBomb is the `{}` spelling of the same bomb.
func emptyObjectValueBomb(n int) string {
	var b strings.Builder
	b.Grow(n*3 + 16)
	b.WriteString(`{a(x:[`)
	for i := 0; i < n; i++ {
		b.WriteString(`{} `)
	}
	b.WriteString(`])}`)
	return b.String()
}

// CAPEC-130: an empty list value is an AST node. A document carrying more of
// them than the budget must be rejected before it is parsed.
func TestAttack_EmptyListValueBombRejected(t *testing.T) {
	q := emptyListValueBomb(MaxQueryNodes + 1)
	if _, err := Parse(q); !errors.Is(err, ErrQueryTooLarge) {
		t.Fatalf("expected ErrQueryTooLarge for %d empty list values, got %v", MaxQueryNodes+1, err)
	}
}

// CAPEC-130: same hole, `{}` spelling.
func TestAttack_EmptyObjectValueBombRejected(t *testing.T) {
	q := emptyObjectValueBomb(MaxQueryNodes + 1)
	if _, err := Parse(q); !errors.Is(err, ErrQueryTooLarge) {
		t.Fatalf("expected ErrQueryTooLarge for %d empty object values, got %v", MaxQueryNodes+1, err)
	}
}

// CAPEC-130: the amplifier spelling — `[]` costs 3 bytes of payload and one AST
// node, so a body far below the 1MB limit must still be bounded. This asserts
// the *allocation* ceiling rather than the node count, so it cannot be satisfied
// by a scan that miscounts in a different direction.
func TestAttack_EmptyContainerAllocationStaysBounded(t *testing.T) {
	q := emptyListValueBomb(100_000)
	if len(q) > 400_000 {
		t.Fatalf("payload grew beyond the intended shape: %d bytes", len(q))
	}
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	if _, err := Parse(q); !errors.Is(err, ErrQueryTooLarge) {
		t.Fatalf("expected the pre-parse scan to reject a 100k-container bomb, got %v", err)
	}
	runtime.ReadMemStats(&m2)
	// A rejected document must not have been parsed at all; the scan is
	// allocation-free, so anything near the parse cost means the AST was built.
	if alloc := m2.TotalAlloc - m1.TotalAlloc; alloc > 4<<20 {
		t.Fatalf("rejection allocated %d bytes; the document was parsed before being rejected", alloc)
	}
}

// The counter direction: a legitimate document with many containers but few
// leaves must still forward. Charging containers must not turn the budget into
// a cap on list *length* — 9,000 short values is still 9,000 nodes.
func TestAttack_LegitContainersStillForward(t *testing.T) {
	// 4,000 fields, each with one single-element list: 4,000 names + 4,000
	// numbers + ~4,000 containers — under the 10,000 budget.
	var b strings.Builder
	b.WriteString("{")
	// Each `fN(x:[1])` is four AST nodes — field name, argument name,
	// ListValue, int value — so 2,000 of them is 8,000 of the 10,000 budget.
	for i := 0; i < 2000; i++ {
		b.WriteString("f")
		b.WriteString(strconv.Itoa(i))
		b.WriteString(`(x:[1]) `)
	}
	b.WriteString("}")
	q := b.String()
	if _, err := Parse(q); err != nil {
		t.Fatalf("legitimate 2000-field document rejected: %v", err)
	}
	// A single large string argument is one node regardless of its length.
	big := `{a(s:"` + strings.Repeat("s", 400_000) + `")}`
	if _, err := Parse(big); err != nil {
		t.Fatalf("400KB single string argument rejected: %v", err)
	}
}
