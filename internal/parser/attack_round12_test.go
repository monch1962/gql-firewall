package parser

import (
	"strings"
	"testing"
	"time"
)

// ── R98: unbounded parser nesting (pre-policy resource exhaustion) ──────────
// The parser runs BEFORE any Rego rule, so a payload that exhausts CPU or
// memory inside parser.ParseQuery is never seen by policy. Measured on
// gqlparser v2.5.34: 300KB of nesting ({a{a{…) burned 4.8s of CPU, and ~900KB
// got the process OOM-killed — the request never reached the firewall's
// depth check, let alone OPA. `parseQueryWithTimeout` cannot help: a timed-out
// goroutine keeps allocating and hoarding a parse-pool slot.
//
// CAPEC-130: Excessive Allocation — adversary supplies a small input that
// expands to unbounded internal allocation, exhausting the target.

// nestedSelection builds `{a{a{...b...}}}` with the requested nesting depth.
// Each level costs 3 bytes, so depth 100000 is ~300KB — inside the default
// 1MB body limit.
func nestedSelection(depth int) string {
	var b strings.Builder
	b.Grow(depth*3 + 8)
	b.WriteString("{")
	for i := 0; i < depth; i++ {
		b.WriteString("a{")
	}
	b.WriteString("b")
	for i := 0; i <= depth; i++ {
		b.WriteString("}")
	}
	return b.String()
}

// nestedListValue builds `{f(x: [[[[…0…]]]])}` with the requested nesting.
func nestedListValue(depth int) string {
	var b strings.Builder
	b.WriteString("{f(x:")
	for i := 0; i < depth; i++ {
		b.WriteString("[")
	}
	b.WriteString("0")
	for i := 0; i < depth; i++ {
		b.WriteString("]")
	}
	b.WriteString(")}")
	return b.String()
}

// CAPEC-130: deeply nested selection set must be rejected by the parser itself.
func TestAttack_ExcessiveSelectionNestingRejected(t *testing.T) {
	const depth = 5000
	start := time.Now()
	_, err := Parse(nestedSelection(depth))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected parser to reject %d-deep nesting, got no error (took %s)", depth, elapsed)
	}
	if elapsed > 2*time.Second {
		t.Errorf("rejection took %s, want < 2s (attacker still burned CPU)", elapsed)
	}
}

// CAPEC-130: the worst case that still fits the default 1MB body limit must be
// rejected fast — not merely survive until the 5s parse timeout.
func TestAttack_NestingDepthAtBodyLimitRejected(t *testing.T) {
	q := nestedSelection(100000)
	if len(q) > DefaultMaxBodyGuess {
		t.Fatalf("test payload %d bytes should fit a 1MB body limit", len(q))
	}

	start := time.Now()
	_, err := Parse(q)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected parser to reject %d-byte nesting payload, got no error (took %s)", len(q), elapsed)
	}
	if elapsed > 1*time.Second {
		t.Errorf("rejection took %s, want < 1s — attacker CPU budget must be tiny", elapsed)
	}
}

// CAPEC-130: nesting inside a single argument value is the same allocation
// amplifier and must also be bounded.
func TestAttack_ExcessiveArgumentValueNestingRejected(t *testing.T) {
	const depth = 5000
	start := time.Now()
	_, err := Parse(nestedListValue(depth))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected parser to reject %d-deep argument value nesting", depth)
	}
	if elapsed > 2*time.Second {
		t.Errorf("rejection took %s, want < 2s", elapsed)
	}
}

// Guard against over-blocking: legitimate deep-but-reasonable queries must
// still parse, and depth accounting must stay exact.
func TestAttack_NestingWithinLimitAccepted(t *testing.T) {
	const depth = 900
	info, err := Parse(nestedSelection(depth))
	if err != nil {
		t.Fatalf("expected %d-deep query to be accepted, got error: %v", depth, err)
	}
	if info.Depth != depth+1 {
		t.Errorf("expected depth %d, got %d", depth+1, info.Depth)
	}
}

// DefaultMaxBodyGuess mirrors proxy.DefaultMaxBodyBytes without importing it
// (parser must not depend on the proxy package).
const DefaultMaxBodyGuess = 1 * 1024 * 1024
