package parser

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/lexer"
)

// ── R98 guard: the nesting pre-scan must match the lexer exactly ────────────
// A pre-parse limit is only sound if it counts the same delimiters the parser
// will descend into. Two failure modes are possible and both are attacks:
//
//	bypass    — scanner ignores delimiters the parser honours (limit defeated)
//	over-block— scanner counts delimiters the parser treats as inert
//	            (legitimate query rejected → self-inflicted DoS)
//
// Both directions must be pinned by tests, because the scanner and gqlparser's
// lexer are independent implementations of the same grammar.

// CAPEC-130: strings and comments are inert to the lexer, so a payload cannot
// smuggle nesting past the limit by quoting it — and must not be blocked for
// containing it either.
func TestAttack_NestingScannerIgnoresInertText(t *testing.T) {
	braces := strings.Repeat("{", 100000)

	cases := []struct {
		name  string
		query string
	}{
		{"string value", `{ f(a: "` + braces + `") }`},
		{"string with escaped quote", `{ f(a: "\"` + braces + `\"") }`},
		{"block string value", `{ f(a: """` + braces + `""") }`},
		{"line comment", "{ f(a: 1) # " + braces + "\n }"},
		{"comment to eof", "{ f(a: 1) } # " + braces},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkNesting(tc.query); err != nil {
				t.Fatalf("inert text wrongly counted as nesting: %v", err)
			}
		})
	}
}

// CAPEC-130: a backslash-escaped triple quote inside a block string must not
// terminate it. If the scanner ends the block string early it counts the
// remaining contents as code — either rejecting a valid document or, worse,
// desynchronising from the lexer for the rest of the payload.
func TestAttack_BlockStringEscapeDoesNotDesynchronise(t *testing.T) {
	// `\"""` is an escaped triple quote: the block string continues.
	query := `{ f(a: """pre \""" ` + strings.Repeat("{", 5000) + ` post""") }`
	if err := checkNesting(query); err != nil {
		t.Fatalf("scanner mis-parsed escaped triple quote: %v", err)
	}
}

// CAPEC-130: object values nest with braces too, so the two delimiter classes
// share one budget. A payload that splits its amplification across them must
// still be caught.
func TestAttack_MixedDelimiterNestingRejected(t *testing.T) {
	const depth = 2000
	var b strings.Builder
	b.WriteString("{ f(a: ")
	for i := 0; i < depth/2; i++ {
		b.WriteString("[{")
	}
	b.WriteString("0")
	for i := 0; i < depth/2; i++ {
		b.WriteString("}]")
	}
	b.WriteString(") }")

	if err := checkNesting(b.String()); !errors.Is(err, ErrNestingTooDeep) {
		t.Fatalf("expected ErrNestingTooDeep for mixed nesting, got %v", err)
	}
}

// CAPEC-130: unbalanced closers must not drive the counter negative, which would
// hand an attacker extra headroom on every subsequent opener.
func TestAttack_UnbalancedClosersDoNotRefundDepth(t *testing.T) {
	query := strings.Repeat("}", 100000) + nestedSelection(MaxQueryNestingDepth+50)
	if err := checkNesting(query); !errors.Is(err, ErrNestingTooDeep) {
		t.Fatalf("expected ErrNestingTooDeep, got %v", err)
	}
}

// CAPEC-130: the scanner and gqlparser's lexer are independent implementations of
// the same literal grammar. A one-index disagreement is a pure bypass: open a
// quote that the scanner honours but the lexer closes, and everything after it is
// invisible to the limit while the parser still recurses into it. Pin the two
// together against the real lexer rather than a hand-written expectation.
func TestAttack_NestingScannerMatchesLexer(t *testing.T) {
	cases := []string{
		// Block strings: quote-run boundaries, escapes, content quotes.
		`"""a"""`, `""""""`, `"""""`, `""""`, `"""a""""`, `""""""""`, `"""""""`,
		`"""\""" still text"""`, `"""a\"""b"""`, `"""# { not a comment }"""`,
		`"""a\"""" b`, `"""\"""\""" x"""`,
		`"""multi
line { """`,
		// Ordinary strings.
		`"ab"`, `""" not block`, `"a\"b"`, `"a\\"`, `"#"`, `"{ not nesting }"`,
	}

	for _, in := range cases {
		full := in + " TAIL"
		l := lexer.New(&ast.Source{Input: full, Name: "t"})
		tok, err := l.ReadToken()

		got := skipLiteral(full, 0)
		if err != nil {
			// Unterminated: the parser rejects the document, so the scan must
			// simply run to EOF and count nothing it swallowed.
			if got != len(full) {
				t.Errorf("%q: unterminated literal, scanner stopped at %d, want %d", in, got, len(full))
			}
			continue
		}
		// tok.Pos.End is NOT the lexer's consumption for a block string: when the
		// closing quote run is longer than three quotes, readBlockString reports
		// firstQuote+3 in the token position while it advances s.end past the whole
		// run. Comparing against Pos.End therefore certified a scanner that stopped
		// at the first `"""` of the run — exactly the desync fixed in R99. The real
		// boundary is where the lexer resumes tokenising, so pin against the start of
		// the following token instead.
		next, nerr := l.ReadToken()
		if nerr != nil {
			t.Fatalf("%q: reading token after literal: %v", in, nerr)
		}
		if next.Kind != lexer.Name || next.Value != "TAIL" {
			t.Fatalf("%q: expected TAIL after literal, got %v %q", in, next.Kind, next.Value)
		}
		want := next.Pos.Start
		for got < len(full) && full[got] == ' ' {
			got++
		}
		if got != want {
			t.Errorf("%q: scanner resumes at %d, lexer at %d (%v)", in, got, want, tok.Kind)
		}
	}
}

// CAPEC-130: an unterminated literal cannot be used to hide nesting, because the
// parser rejects the document anyway — but the scan must not itself panic or
// mis-count while walking to EOF.
func TestAttack_UnterminatedLiteralIsNotNesting(t *testing.T) {
	for _, q := range []string{
		`{ f(a: "unterminated`,
		"{ f(a: \"\"\"unterminated",
		"{ f(a: 1) # unterminated comment",
		"{ f(a: \"\\",
	} {
		if err := checkNesting(q); err != nil {
			t.Fatalf("unterminated literal wrongly reported as nesting: %v (%q)", err, q)
		}
	}
}

func TestAttack_NestingScannerBoundIsExact(t *testing.T) {
	// Guard against over-blocking: the limit must admit everything up to the
	// documented bound, and the rejection must be cheap (a hard-DoS check that
	// itself costs seconds is not a defence).
	atLimit := strings.Repeat("{", MaxQueryNestingDepth)
	if err := checkNesting(atLimit); err != nil {
		t.Fatalf("depth %d should be allowed: %v", MaxQueryNestingDepth, err)
	}
	if err := checkNesting(atLimit + "{"); !errors.Is(err, ErrNestingTooDeep) {
		t.Fatalf("depth %d should be rejected, got %v", MaxQueryNestingDepth+1, err)
	}

	// Rejection cost must be proportional to the bytes *up to* the limit, not to
	// the total payload: stop at the first violation.
	huge := atLimit + strings.Repeat("{", 4*1024*1024)
	start := time.Now()
	if err := checkNesting(huge); !errors.Is(err, ErrNestingTooDeep) {
		t.Fatalf("expected rejection of oversized payload, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("early rejection took %s, want < 100ms", elapsed)
	}
}

// CAPEC-130: a nesting bomb delivered through the public Parse entry point must
// leave no partial QueryInfo behind for callers to act on.
func TestAttack_RejectedNestingReturnsNoInfo(t *testing.T) {
	info, err := Parse(nestedSelection(50000))
	if err == nil {
		t.Fatal("expected rejection")
	}
	if info != nil {
		t.Errorf("expected nil QueryInfo on rejection, got %+v", info)
	}
	if !errors.Is(err, ErrNestingTooDeep) {
		t.Errorf("expected ErrNestingTooDeep sentinel, got %v", err)
	}
}
