package parser

import (
	"errors"
	"strings"
	"testing"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/lexer"
)

// ── R99: the R98 nesting pre-scan must end literals where the lexer does ────
// The pre-parse nesting limit is only a limit if it counts the same delimiters
// gqlparser descends into. Two literal boundaries were scanned wrong, and both
// errors point the dangerous way — the scanner swallows text the parser still
// lexes, so a nesting bomb placed after the desync point is invisible to the
// limit and reaches the recursive descent unfettered (CAPEC-130).
//
//	comment    — the scan ran a `#` comment to '\n' only; gqlparser ends it at
//	             any byte <= 0x1f except tab, so a lone '\r' ends the comment
//	             for the parser while the scanner keeps skipping.
//	block str. — the scan ended a block string at the *first* `"""` of a closing
//	             quote run; gqlparser consumes the whole run, so the scanner is
//	             left inside a phantom ordinary string and skips the remainder
//	             of the document.
//
// Both are pure undercounts, i.e. bypasses of the R98 bound.

const bombDepth = 1500

// lexerMaxDepth walks the real lexer over doc and reports the deepest run of
// unclosed BraceL/BracketL tokens. This is the ground truth the pre-scan is
// pinned to — token kinds, not character arithmetic — so it cannot inherit the
// scanner's own idea of where a literal ends.
func lexerMaxDepth(t *testing.T, doc string) int {
	t.Helper()
	l := lexer.New(&ast.Source{Input: doc, Name: "t"})
	depth, maxDepth := 0, 0
	for {
		tok, err := l.ReadToken()
		if err != nil {
			t.Fatalf("lexer error: %v", err)
		}
		switch tok.Kind {
		case lexer.EOF:
			return maxDepth
		case lexer.BraceL, lexer.BracketL:
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case lexer.BraceR, lexer.BracketR:
			if depth > 0 {
				depth--
			}
		}
	}
}

// commentDesyncPayload builds a `#` comment terminated by term, followed by a
// syntactically valid nesting bomb.
func commentDesyncPayload(term string) string {
	var b strings.Builder
	b.WriteString("# leading comment")
	b.WriteString(term)
	b.WriteString(strings.Repeat("{a", bombDepth))
	b.WriteString(strings.Repeat("}", bombDepth))
	return b.String()
}

// quoteRunDesyncPayload builds a block string that closes with a four-quote run
// (`"""x""""`), so the parser consumes all four quotes and the following
// brackets are code, while a scanner that stops at the first `"""` treats the
// next quote as opening an ordinary string that runs to EOF.
func quoteRunDesyncPayload() string {
	var b strings.Builder
	b.WriteString(`{ f(a: ["""x""""`)
	b.WriteString(strings.Repeat("[", bombDepth))
	b.WriteString(strings.Repeat("]", bombDepth))
	b.WriteString("]) }")
	return b.String()
}

// CAPEC-130: gqlparser's readComment ends at any byte <= 0x1f except tab, not
// only at '\n'. A lone CR therefore hands the parser a nesting bomb the scanner
// never counted.
func TestAttack_CommentEndsWhereLexerEnds(t *testing.T) {
	for _, tc := range []struct {
		name string
		term string
	}{
		{"carriage return", "\r"},
		{"crlf", "\r\n"},
		{"line feed", "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := commentDesyncPayload(tc.term)
			if got := lexerMaxDepth(t, payload); got <= MaxQueryNestingDepth {
				t.Fatalf("payload is not a bomb: lexer max depth %d", got)
			}
			if err := checkNesting(payload); !errors.Is(err, ErrNestingTooDeep) {
				t.Errorf("expected ErrNestingTooDeep for %s-terminated comment, got %v", tc.name, err)
			}
		})
	}
}

// CAPEC-130: a closing quote run longer than three quotes must be consumed
// whole, exactly as gqlparser's readBlockString does, or the trailing quote
// opens a phantom string and everything after it escapes the depth limit.
func TestAttack_BlockStringQuoteRunDoesNotDesync(t *testing.T) {
	payload := quoteRunDesyncPayload()
	if got := lexerMaxDepth(t, payload); got <= MaxQueryNestingDepth {
		t.Fatalf("payload is not a bomb: lexer max depth %d", got)
	}
	if err := checkNesting(payload); !errors.Is(err, ErrNestingTooDeep) {
		t.Errorf("expected ErrNestingTooDeep after four-quote block string, got %v", err)
	}
}

// CAPEC-130: every payload the lexer sees nest past the bound must be rejected,
// and everything it does not must be admitted. Pin the whole scan — not one
// token's end index — because a position quirk in the token can agree with a
// wrong scan while the parser's actual consumption disagrees.
func TestAttack_NestingScanAgreesWithLexer(t *testing.T) {
	docs := []struct {
		name  string
		query string
	}{
		{"comment ends at CR", commentDesyncPayload("\r")},
		{"comment ends at CRLF", commentDesyncPayload("\r\n")},
		{"comment ends at LF", commentDesyncPayload("\n")},
		{"four-quote block string", quoteRunDesyncPayload()},
		{"five-quote block string", `{ f(a: ["""x"""""` + strings.Repeat("[", bombDepth) + strings.Repeat("]", bombDepth) + "]) }"},
		{"six-quote block string", `{ f(a: ["""x""""""` + strings.Repeat("[", bombDepth) + strings.Repeat("]", bombDepth) + "]) }"},
		{"plain nesting bomb", strings.Repeat("{a", bombDepth) + strings.Repeat("}", bombDepth)},
		{"escaped triple quote keeps literal open",
			`{ f(a: """pre \""" ` + strings.Repeat("{", 5000) + ` post""") }`},
		{"braces in CR-terminated comment are inert", "{ f(a: 1) } # {\r{ f(b: 2) }"},
		{"braces in block string are inert", `{ f(a: """{` + strings.Repeat("{", 5000) + `}""") }`},
		{"four-quote block string is inert", `{ f(a: """a{` + strings.Repeat("{", 5000) + `b"""" ) }`},
		{"shallow document", `{ a { b { c } } }`},
	}

	for _, tc := range docs {
		t.Run(tc.name, func(t *testing.T) {
			want := lexerMaxDepth(t, tc.query)
			err := checkNesting(tc.query)
			switch {
			case want > MaxQueryNestingDepth && !errors.Is(err, ErrNestingTooDeep):
				t.Errorf("lexer nests %d deep but scan admitted the document (err=%v)", want, err)
			case want <= MaxQueryNestingDepth && err != nil:
				t.Errorf("lexer nests only %d deep but scan rejected: %v", want, err)
			}
		})
	}
}

// CAPEC-130: the bypass must be closed at the public entry point too, and leave
// no partial QueryInfo for callers to act on.
func TestAttack_CommentDesyncRejectedByParse(t *testing.T) {
	info, err := Parse(commentDesyncPayload("\r"))
	if !errors.Is(err, ErrNestingTooDeep) {
		t.Fatalf("expected ErrNestingTooDeep from Parse, got %v", err)
	}
	if info != nil {
		t.Errorf("expected nil QueryInfo on rejection, got %+v", info)
	}
}
