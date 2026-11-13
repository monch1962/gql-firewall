package parser

import (
	"errors"
	"fmt"
)

// MaxQueryNestingDepth bounds how deeply `{` and `[` may nest inside a query
// document.
//
// gqlparser's parser is recursive descent with no depth limit of its own, and it
// runs before any Rego rule, so a payload's nesting is amplified into parser
// stack frames and allocations that the firewall's depth/cost policy never gets
// to see. Measured on gqlparser v2.5.34: a 300KB nested selection burned 2.4s of
// CPU and ~900KB got the sidecar OOM-killed. Bounding nesting before the parse
// is the only place the amplifier can be cut, because a timed-out parse
// goroutine keeps allocating.
//
// CAPEC-130: Excessive Allocation.
const MaxQueryNestingDepth = 1024

// ErrNestingTooDeep is returned when a query nests braces or brackets past
// MaxQueryNestingDepth. It is a sentinel so callers can classify the rejection
// without matching on message text.
var ErrNestingTooDeep = errors.New("query nesting too deep")

// checkNesting performs a single linear, allocation-free scan of the raw query
// text and reports ErrNestingTooDeep as soon as the brace/bracket nesting depth
// exceeds MaxQueryNestingDepth.
//
// It must run before parsing: the recursive descent itself is the amplifier. The
// scan understands the lexical structure of a GraphQL document — line comments,
// ordinary strings and triple-quoted block strings — so delimiters inside those
// constructs are not counted. Skipping string bodies is not merely cosmetic: if
// the scanner desynchronised from gqlparser's lexer, an attacker could open a
// quote to make the scanner swallow a nesting bomb that the parser then walks.
// The two implementations therefore have to agree on where every literal ends.
func checkNesting(query string) error {
	depth := 0
	n := len(query)

	for i := 0; i < n; {
		switch query[i] {
		case '#':
			// Line comment: runs to the end of the line or the document.
			for i < n && query[i] != '\n' {
				i++
			}

		case '"':
			i = skipLiteral(query, i)

		case '{', '[':
			depth++
			if depth > MaxQueryNestingDepth {
				return fmt.Errorf("%w: more than %d levels", ErrNestingTooDeep, MaxQueryNestingDepth)
			}
			i++

		case '}', ']':
			// Unbalanced closers must not refund depth, or a prefix of `}` would
			// buy the attacker extra headroom for every subsequent opener.
			if depth > 0 {
				depth--
			}
			i++

		default:
			i++
		}
	}
	return nil
}

// skipLiteral returns the index just past the string or block string that opens at
// index i — i.e. the bound gqlparser's lexer reports for that token.
func skipLiteral(query string, i int) int {
	if i+2 < len(query) && query[i+1] == '"' && query[i+2] == '"' {
		return skipBlockString(query, i)
	}
	return skipString(query, i)
}

// skipString returns the index just past the ordinary string that opens at
// index i, honouring backslash escapes so that \" does not end it.
func skipString(query string, i int) int {
	n := len(query)
	i++ // opening quote
	for i < n {
		switch query[i] {
		case '\\':
			i += 2 // escaped character (or \uXXXX's 'u'; digits never nest)
		case '"':
			return i + 1
		default:
			i++
		}
	}
	return n
}

// skipBlockString returns the index just past the block string that opens at
// index i (the first of the opening `"""`).
//
// It mirrors gqlparser's readBlockString: `\"""` is an escape sequence and the
// literal ends at the very next `"""` — exactly three quotes. Quotes beyond that
// closing triple are *not* part of the literal; they open a following token.
// Over-extending the literal is the dangerous direction: everything the scanner
// thinks is string content is skipped by the nesting check while the parser still
// descends into it, so the limit could be defeated with nothing but extra quotes.
func skipBlockString(query string, i int) int {
	n := len(query)
	i += 3 // opening """

	for i < n {
		if query[i] == '\\' && i+3 < n &&
			query[i+1] == '"' && query[i+2] == '"' && query[i+3] == '"' {
			i += 4 // escaped triple quote: still inside the literal
			continue
		}
		if query[i] == '"' && i+2 < n && query[i+1] == '"' && query[i+2] == '"' {
			return i + 3
		}
		i++
	}
	return n
}
