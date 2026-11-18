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

// MaxQueryNodes bounds how many AST-node-producing tokens the pre-parse scan
// will admit in one document: name, number, string and block-string literals.
//
// Bounding nesting (R98) cut the stack amplifier but not the heap one. gqlparser
// allocates an AST node per field, alias, enum and value, measured at ~282 bytes
// of allocation per byte of flat payload: a 1MB body of `{a a a …}` is 524,287
// field nodes, 147.7MB allocated and 123.6MB retained, at depth 1 — so every
// depth/cost rule passes it. The parse pool admits 64 such parses at once
// (~7.9GB) and the sidecar is OOM-killed (CAPEC-130: Excessive Allocation).
//
// The request body limit cannot stand in for this budget: it bounds the input
// bytes, not the expansion. 10,000 nodes is ~2.8MB of AST (measured) — two
// orders of magnitude above any hand-written query, and the cap on the
// worst case a saturated pool can reach.
const MaxQueryNodes = 10000

// ErrNestingTooDeep is returned when a query nests braces or brackets past
// MaxQueryNestingDepth. It is a sentinel so callers can classify the rejection
// without matching on message text.
var ErrNestingTooDeep = errors.New("query nesting too deep")

// ErrQueryTooLarge is returned when a document carries more than MaxQueryNodes
// name/number tokens, i.e. when parsing it would expand into an AST far larger
// than the request that produced it.
var ErrQueryTooLarge = errors.New("query exceeds node budget")

// countQueryNodes reports how many name and number tokens a document contains,
// counting only tokens that become AST nodes. It is the budget metric used by
// scanQuery; over-counting is safe (a false rejection), under-counting is a
// bypass, so it deliberately counts conservatively.
func countQueryNodes(query string) int {
	nodes, _ := scanQueryNodes(query, 0)
	return nodes
}

// scanQuery performs a single linear, allocation-free scan of the raw query
// text and rejects it as soon as either budget is exceeded: brace/bracket
// nesting past MaxQueryNestingDepth, or more than MaxQueryNodes node tokens.
//
// It must run before parsing: the recursive descent itself is the amplifier for
// both resources (stack and heap). The scan understands the lexical structure of
// a GraphQL document — line comments, ordinary strings and triple-quoted block
// strings — so delimiters and name-like bytes inside those constructs are not
// counted. Skipping string bodies is not merely cosmetic: if the scanner
// desynchronised from gqlparser's lexer, an attacker could open a quote to make
// the scanner swallow a nesting bomb or a field bomb that the parser then walks.
// The two implementations therefore have to agree on where every literal ends.
func scanQuery(query string) error {
	_, err := scanQueryNodes(query, MaxQueryNodes)
	return err
}

// scanQueryNodes is the shared implementation. maxNodes <= 0 means unlimited
// (used by countQueryNodes); the depth bound always applies.
func scanQueryNodes(query string, maxNodes int) (int, error) {
	depth := 0
	nodes := 0
	n := len(query)

	// addNode charges one AST node against the budget. It returns true when the
	// budget is exhausted, so every node-producing branch rejects at the first
	// violation and cost stays proportional to the bytes up to the limit.
	addNode := func() bool {
		nodes++
		return maxNodes > 0 && nodes > maxNodes
	}

	for i := 0; i < n; {
		c := query[i]
		switch {
		case c == '#':
			// Line comment. gqlparser's readComment consumes every byte with
			// `r > 0x1f || r == '	'` — a lone '\r' (or any other control byte)
			// ends the comment there, not only '\n'. Scanning to '\n' alone
			// would swallow the rest of the document on a CR-terminated
			// comment, hiding a nesting bomb the parser then admits.
			for i < n && (query[i] > 0x1f || query[i] == '	') {
				i++
			}

		case c == '"':
			// A string or block string is one ast.Value node. Only the bytes
			// *inside* the literal are inert; the node the lexer emits is not,
			// so it has to be charged or a list of short literals is a value
			// bomb that the budget never sees (CAPEC-130).
			if addNode() {
				return nodes, fmt.Errorf("%w: more than %d nodes", ErrQueryTooLarge, maxNodes)
			}
			i = skipLiteral(query, i)

		case c == '{' || c == '[':
			depth++
			if depth > MaxQueryNestingDepth {
				return nodes, fmt.Errorf("%w: more than %d levels", ErrNestingTooDeep, MaxQueryNestingDepth)
			}
			i++

		case c == '}' || c == ']':
			// Unbalanced closers must not refund depth, or a prefix of `}` would
			// buy the attacker extra headroom for every subsequent opener.
			if depth > 0 {
				depth--
			}
			i++

		case isNameStart(c) || isDigit(c) || (c == '-' && i+1 < n && isDigit(query[i+1])):
			// A name or number token: one AST node each (field, alias, enum,
			// fragment/type name, or value). Consume the whole run so multi-byte
			// tokens count once. A '.' inside a float splits the run but only
			// over-counts, which is the safe direction.
			if addNode() {
				return nodes, fmt.Errorf("%w: more than %d nodes", ErrQueryTooLarge, maxNodes)
			}
			i++
			for i < n && (isNameChar(query[i]) || query[i] == '-') {
				i++
			}

		default:
			i++
		}
	}
	return nodes, nil
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isNameChar(c byte) bool {
	return isNameStart(c) || isDigit(c)
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
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
