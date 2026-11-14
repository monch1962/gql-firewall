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
			// Line comment. gqlparser's readComment consumes every byte with
			// `r > 0x1f || r == '	'` — a lone '\r' (or any other control byte)
			// ends the comment there, not only '\n'. Scanning to '\n' alone
			// would swallow the rest of the document on a CR-terminated
			// comment, hiding a nesting bomb the parser then admits.
			for i < n && (query[i] > 0x1f || query[i] == '	') {
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
// literal is closed by a run of three or more quotes — the lexer consumes the
// whole run (`s.end += quoteCount`), treating the extra quotes as content. A
// scanner that stopped at the first `"""` of the run would leave a dangling
// quote that it then reads as an ordinary string, swallowing the rest of the
// document while the parser keeps lexing and descending into it. Over-extending
// the literal is the dangerous direction, so the run must be consumed exactly.
func skipBlockString(query string, i int) int {
	n := len(query)
	i += 3 // opening """

	for i < n {
		if query[i] == '\\' && i+3 < n &&
			query[i+1] == '"' && query[i+2] == '"' && query[i+3] == '"' {
			i += 4 // escaped triple quote: still inside the literal
			continue
		}
		if query[i] == '"' {
			j := i
			for j < n && query[j] == '"' {
				j++
			}
			if j-i >= 3 {
				return j // closing run of >= 3 quotes, consumed whole
			}
			i = j // one or two quotes are literal content
			continue
		}
		i++
	}
	return n
}
