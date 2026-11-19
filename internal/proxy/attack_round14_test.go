package proxy

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// slowValidQuery builds a syntactically valid, schema-free document that is as
// expensive to parse as the firewall will ever admit: deep-but-admissible
// nesting (512 levels, well under MaxQueryNestingDepth) plus flat selections up
// to the MaxQueryNodes budget (~8,900 field nodes, ~19KB).
//
// R101's node budget caps how slow a single parse can be, so this is the new
// worst case (~8ms measured). That is still several times ParseTimeout below,
// which is the property these tests need: a parse that outlives the caller's
// wait without tripping any depth or size rule.
//
// R103 charges container tokens too, so each of the 512 `{a` levels now costs
// two nodes (the selection set and the field name) instead of one; the flat
// tail is sized to leave the document just inside the budget.
func slowValidQuery() string {
	const levels = 512
	var b strings.Builder
	b.Grow(levels*4 + 20000)
	b.WriteString(strings.Repeat("{a", levels))
	for i := 0; i < 8900; i++ {
		b.WriteString("b ")
	}
	b.WriteString(strings.Repeat("}", levels))
	return b.String()
}

// CAPEC-130: Excessive Allocation — a parse pool that refunds its slot when the
// *caller* stops waiting is not a bound. A timeout abandons the wait, not the
// work: the goroutine keeps allocating and burning CPU, so the next request
// takes the freed slot and the cap of N concurrent parses becomes unbounded.
//
// With `--max-body-mb` tunable (and 0 = unlimited) a single admitted body can
// outlive ParseTimeout by orders of magnitude, which is exactly how the refund
// is reached. The slot must be released when the parse work finishes.
func TestAttack_ParseTimeoutDoesNotRefundPoolSlot(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	h.SetParseConcurrency(1)
	h.ParseTimeout = time.Millisecond

	slow := slowValidQuery() // ~8ms to parse: ~8x the timeout

	// Prove the payload really is slower than the timeout, so the rest of the
	// test cannot degrade into a flaky no-op on a fast machine.
	t0 := time.Now()
	if _, err := parseQueryWithTimeout(slow, 30*time.Second); err != nil {
		t.Fatalf("slow payload should parse successfully: %v", err)
	}
	if cost := time.Since(t0); cost < 3*time.Millisecond {
		t.Skipf("payload parsed in %s — too fast to exercise the timeout window", cost)
	}

	// First request: legitimately allowed, then times out. Its parse goroutine
	// is still running when this returns.
	if _, err := h.parse(slow); err == nil {
		t.Fatal("expected the slow parse to time out")
	}

	// Second request, issued while the first parse is still burning CPU: the
	// pool is full, so it must be refused rather than admitted.
	if _, err := h.parse("{a}"); !errors.Is(err, errParseBusy) {
		t.Fatalf("parse pool refunded a slot on timeout: second parse was admitted (err=%v) while the abandoned goroutine still runs — concurrency cap is unbounded", err)
	}
}

// CAPEC-130: the mirror-image failure. Holding the slot until the work finishes
// must not leak it: once the abandoned parse drains, the pool has to accept
// requests again or a short burst of slow queries would wedge the firewall
// permanently (a DoS that fixes one DoS with another).
func TestAttack_ParsePoolRecoversAfterSlowParse(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	h.SetParseConcurrency(1)
	h.ParseTimeout = time.Millisecond

	if _, err := h.parse(slowValidQuery()); err == nil {
		t.Fatal("expected the slow parse to time out")
	}

	deadline := time.Now().Add(15 * time.Second)
	for {
		_, err := h.parse("{a}")
		if err == nil {
			return // slot reclaimed: pool recovered
		}
		if !errors.Is(err, errParseBusy) {
			t.Fatalf("unexpected error while waiting for the pool to drain: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("parse slot never reclaimed after the abandoned parse finished — pool is permanently wedged")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
