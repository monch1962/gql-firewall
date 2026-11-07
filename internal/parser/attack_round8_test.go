package parser

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ── R90: Fragment deduplication undercounts depth ───────────────────────────
// Not in CAPEC: depth-limit evasion. A single global `visited` set means a
// fragment is analysed only at its first (shallowest) spread; every deeper
// spread of the same fragment is skipped, so the reported depth — and the
// depth limit derived from it — is attacker-controlled.
func TestAttack_FragmentDedupDepthUndercount(t *testing.T) {
	// Branch 1 spreads F at depth 1 (fields d@2, e@3).
	// Branch 2 spreads F at depth 2 (fields d@3, e@4).
	// True depth is 4 and true field count is 7.
	query := `query {
		a { ...F }
		b { c { ...F } }
	}
	fragment F on T { d { e } }`

	info, err := Parse(query)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if info.Depth != 4 {
		t.Errorf("depth undercounted: got %d, want 4 — a deep fragment spread is skipped because a shallow one was seen first", info.Depth)
	}
	if info.FieldCount != 7 {
		t.Errorf("field count undercounted: got %d, want 7", info.FieldCount)
	}
}

// A fragment spread three levels down must still contribute its full depth.
func TestAttack_FragmentDepthThreeSpreads(t *testing.T) {
	query := `query {
		l1 { ...F }
		l1 { l2 { l3 { ...F } } }
	}
	fragment F on T { x { y { z } } }`

	info, err := Parse(query)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	// Deepest path: l1(1) l2(2) l3(3) x(4) y(5) z(6).
	if info.Depth != 6 {
		t.Errorf("depth undercounted: got %d, want 6", info.Depth)
	}
}

// ── Guard: memoising fragments must not reintroduce exponential blowup ──────
// Each fragment spreads the next twice, so an unmemoised walk is O(2^40).
// Already safe before the fix (the visited set collapsed it); this guards the
// fix against regressing into an amplifier.
func TestGuard_FragmentExplosionBounded(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("query { ...F0 }\n")
	for i := 0; i < 40; i++ {
		sb.WriteString(fmt.Sprintf("fragment F%d on T { ...F%d ...F%d }\n", i, i+1, i+1))
	}
	sb.WriteString("fragment F40 on T { leaf }\n")

	done := make(chan struct{})
	go func() {
		_, _ = Parse(sb.String())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("fragment analysis did not terminate within 2s — amplifier reintroduced")
	}
}
