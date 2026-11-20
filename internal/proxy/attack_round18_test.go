package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/monch1962/gql-firewall/internal/parser"
)

// ── R104: the node budget must bind EVERY request path, including GET ───────
// R101-R103 pinned the AST budget on the POST body path and the batch
// envelope. The GraphQL-over-HTTP GET path (`?query=`) reaches the parser
// through a different branch, and nothing failed if that branch stopped
// scanning: with an allowing evaluator a GET bomb would forward to the
// upstream and expand into a full AST there. The budget is a fixed constant,
// so the only thing that keeps GET bounded is that its branch calls the same
// budgeted parse — this test pins that wiring rather than the parser.
//
// CAPEC-130: Excessive Allocation.
func flatSelectionQuery(n int) string {
	var b strings.Builder
	b.Grow(n*2 + 2)
	b.WriteString("{")
	for i := 0; i < n; i++ {
		b.WriteString("a ")
	}
	b.WriteString("}")
	return b.String()
}

func TestAttack_NodeBudgetAppliesToGETPath(t *testing.T) {
	calls := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	// One node over the budget, before the flattening of `{` itself — enough
	// to be over the limit, small enough to be a legal URL.
	bomb := flatSelectionQuery(parser.MaxQueryNodes + 1)
	target := "/graphql?query=" + url.QueryEscape(bomb)

	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()

	start := time.Now()
	h.ServeHTTP(w, req)
	elapsed := time.Since(start)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for an over-budget GET query, got %d (%s)", w.Code, w.Body.String())
	}
	if calls != 0 {
		t.Errorf("upstream was called %d times for a rejected GET query", calls)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("rejection took %s — the node budget did not run before the parse", elapsed)
	}
	if strings.Contains(w.Body.String(), "a a a") {
		t.Errorf("response echoed attacker payload: %q", w.Body.String())
	}
}

// CAPEC-130: the mirror image. A legitimate GET query under the budget must
// still be inspected and forwarded — a budget that rejects real traffic on one
// path is a self-inflicted DoS, and a test that only asserts rejections would
// pass against a GET branch that blocks everything.
func TestAttack_LegitLargeGETStillForwarded(t *testing.T) {
	calls := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	// Well under the budget (default depth/cost policy permits it) but large
	// enough that it would trip any path that measured the URL instead of the
	// document.
	legit := flatSelectionQuery(parser.MaxQueryNodes / 20)
	req := httptest.NewRequest(http.MethodGet, "/graphql?query="+url.QueryEscape(legit), nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected an under-budget GET query to forward, got %d (%s)", w.Code, w.Body.String())
	}
	if calls != 1 {
		t.Errorf("expected upstream to be called once, got %d", calls)
	}
}
