package parser

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/lexer"
)

// trueMaxDepth walks gqlparser's real lexer and reports the deepest BraceL /
// BracketL nesting it produced. Depth reached *before* a lexer error still
// counts: the parser builds the AST lazily as it lexes, so it has already
// recursed by the time the error is raised.
func trueMaxDepth(input string) int {
	l := lexer.New(&ast.Source{Input: input, Name: "t"})
	depth, max := 0, 0
	for {
		tok, err := l.ReadToken()
		if err != nil {
			return max
		}
		switch tok.Kind {
		case lexer.EOF:
			return max
		case lexer.BraceL, lexer.BracketL:
			depth++
			if depth > max {
				max = depth
			}
		case lexer.BraceR, lexer.BracketR:
			if depth > 0 {
				depth--
			}
		}
	}
}

// assertNoBypass enforces the only security-relevant direction of the scan: if
// checkNesting admits a document, the real lexer must not nest deeper than the
// bound. Over-blocking is a availability question tested elsewhere; undercounting
// is a bypass and must never happen.
func assertNoBypass(t *testing.T, desc, input string) {
	t.Helper()
	if scanQuery(input) != nil {
		return
	}
	if d := trueMaxDepth(input); d > MaxQueryNestingDepth {
		t.Errorf("BYPASS %s: scanner admitted %d-byte document, real lexer depth %d", desc, len(input), d)
	}
}

// CAPEC-130: R99 pinned the scanner's literal boundaries against a fixed table of
// quote/comment shapes. A table only covers the combinations someone thought of,
// and a single-index desync is a pure bypass (open a literal the scanner honours
// but the lexer closes, and the bomb behind it is invisible to the limit). This
// fuzzes the invariant instead: for every construction the scanner admits, the
// real lexer must never nest past the bound.
func TestAttack_NestingScannerResyncCrossProduct(t *testing.T) {
	pieces := []string{
		"", " ", "\n", "\r", "\t", "#", "#c\r", "a", "0",
		`"`, `""`, `"""`, `""""`, `"""a"""`, `"a"`, `"\\"`,
		`\`, `\\`, `\"""`, `"""\"""`,
		"\u00e9", "\x00", "{", "}",
	}
	bomb := strings.Repeat("{", MaxQueryNestingDepth+2)

	for _, p1 := range pieces {
		for _, p2 := range pieces {
			assertNoBypass(t, "pre/post "+p1+"/"+p2, p1+bomb+p2)
			if unit := p1 + "{" + p2; len(unit) > 1 {
				// Noise between every brace: worst case for resynchronisation.
				assertNoBypass(t, "interleaved "+p1+"/"+p2,
					strings.Repeat(unit, MaxQueryNestingDepth+2))
			}
			assertNoBypass(t, "enclosed "+p1+"/"+p2, p1+bomb+p1+bomb+p2)
		}
	}

	// Escape parity and quote-run boundaries — the classic off-by-one shapes.
	for k := 0; k <= 12; k++ {
		assertNoBypass(t, "backslash run", `"`+strings.Repeat(`\`, k)+`"`+bomb+`"`)
		assertNoBypass(t, "backslash run in block", `"""`+strings.Repeat(`\`, k)+bomb+`"""`)
		assertNoBypass(t, "quote run", `"""`+strings.Repeat(`"`, k)+bomb+`"""`)
		assertNoBypass(t, "comment tail", "#"+strings.Repeat("x", k)+"\r"+bomb)
	}
}

// CAPEC-130: seeded structural fuzz. Noise is interleaved with a nesting bomb of
// random depth around the bound, so random cases can actually cross it — a purely
// short-input fuzz never reaches 1024 levels and certifies nothing.
func TestAttack_NestingScannerStructuralFuzz(t *testing.T) {
	pieces := []string{
		"{", "}", "[", "]", `"`, `"""`, `\`, "#", "a", " ", "\n", "\r", "\t",
		`\"""`, `""`, "0", "\u00e9", "\x00", "#c\r", `""""`,
	}
	rng := rand.New(rand.NewSource(20261117))
	for n := 0; n < 20000; n++ {
		depth := MaxQueryNestingDepth - 3 + rng.Intn(7)
		var sb strings.Builder
		for i := 0; i < depth; i++ {
			sb.WriteString(pieces[rng.Intn(len(pieces))])
			sb.WriteString("{")
		}
		for i := 0; i < depth; i++ {
			sb.WriteString("}")
		}
		assertNoBypass(t, "structural fuzz", sb.String())
	}
}
