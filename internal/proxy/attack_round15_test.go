package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── R101: AST amplification over the wire ───────────────────────────────────
// The parser-level budget only protects the sidecar if every request path runs
// through it. A 1MB body of flat selections is valid JSON, valid GraphQL, depth
// 1 and inside the body limit — so this asserts the handler rejects it before
// the parse allocates ~148MB, and that the upstream never sees it.
//
// CAPEC-130: Excessive Allocation.
func TestAttack_FlatSelectionBombRejectedAtHTTP(t *testing.T) {
	calls := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	var q strings.Builder
	q.WriteString("{")
	for q.Len() < 400_000 {
		q.WriteString("a ")
	}
	q.WriteString("}")
	body := fmt.Sprintf(`{"query":%q}`, q.String())

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	start := time.Now()
	h.ServeHTTP(w, req)
	elapsed := time.Since(start)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for amplified document, got %d (%s)", w.Code, w.Body.String())
	}
	if calls != 0 {
		t.Errorf("upstream was called %d times for a rejected document", calls)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("rejection took %s — the node budget did not run before the parse", elapsed)
	}
	if strings.Contains(w.Body.String(), "a a a") {
		t.Errorf("response echoed attacker payload: %q", w.Body.String()[:120])
	}
}

// CAPEC-130: the mirror image — legitimate large queries must still be
// forwarded. A budget that rejects real traffic is a self-inflicted DoS.
func TestAttack_LegitLargeQueryStillForwarded(t *testing.T) {
	calls := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	// 2,000 aliased fields on one selection set: large, but inside the budget.
	var q strings.Builder
	q.WriteString("{")
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&q, "a%d:field ", i)
	}
	q.WriteString("}")
	body := fmt.Sprintf(`{"query":%q}`, q.String())

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("legitimate large query rejected with %d (%s)", w.Code, w.Body.String())
	}
	if calls != 1 {
		t.Errorf("expected upstream to be called once, got %d", calls)
	}
}
