package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── R103: empty-container value bomb over the wire ─────────────────────────
// R102 charged string literals but still left `{` and `[` free, so an *empty*
// container — `[]` / `{}`, both valid GraphQL values that materialise an
// ast.ListValue / ast.ObjectValue — cost 3 bytes of payload and no budget at
// all. A 300KB body of 100,000 empty lists was a depth-1 document the scan
// scored as 2 nodes; it parsed and allocated 31.3MB, 11x the ceiling.
//
// This asserts the wire behaviour: rejected before the upstream is reached, and
// rejected identically inside a batch envelope (which would otherwise multiply
// the expansion by the batch size).
//
// CAPEC-130: Excessive Allocation.
func emptyListBombQuery(n int) string {
	var b strings.Builder
	b.Grow(n*3 + 16)
	b.WriteString(`{a(x:[`)
	for i := 0; i < n; i++ {
		b.WriteString(`[] `)
	}
	b.WriteString(`])}`)
	return b.String()
}

func TestAttack_EmptyContainerBombRejectedAtHTTP(t *testing.T) {
	calls := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	body := fmt.Sprintf(`{"query":%q}`, emptyListBombQuery(100_000))
	if len(body) > 1024*1024 {
		t.Fatalf("payload is %d bytes, above the 1MB body limit — it would be rejected as oversized instead of by the budget", len(body))
	}

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for the empty-container bomb, got %d", w.Code)
	}
	if calls != 0 {
		t.Errorf("expected the upstream never to be reached, got %d calls", calls)
	}
}

func TestAttack_EmptyContainerBombRejectedInBatch(t *testing.T) {
	calls := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	bomb := emptyListBombQuery(20_000) // each item alone exceeds the 10,000-node budget
	var batch strings.Builder
	batch.WriteString("[")
	for i := 0; i < 4; i++ {
		if i > 0 {
			batch.WriteString(",")
		}
		batch.WriteString(fmt.Sprintf(`{"query":%q}`, bomb))
	}
	batch.WriteString("]")
	if batch.Len() > 1024*1024 {
		t.Fatalf("batch is %d bytes, above the body limit — it would be rejected as oversized", batch.Len())
	}

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(batch.String()))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for a batch of empty-container bombs, got %d", w.Code)
	}
	if calls != 0 {
		t.Errorf("expected the upstream never to be reached, got %d calls", calls)
	}
}

// The counter direction: a document with many containers but a legitimate shape
// must still forward. Charging containers must not become a cap on list length
// for ordinary queries.
func TestAttack_ManyShortListValuesStillForwarded(t *testing.T) {
	calls := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	// 1,000 fields each carrying a 3-element list: 1,000 names + 1,000 arg
	// names + 1,000 list containers + 3,000 ints = 6,000 nodes, comfortably
	// inside the 10,000 budget.
	var q strings.Builder
	q.WriteString("{")
	for i := 0; i < 1000; i++ {
		q.WriteString(fmt.Sprintf("f%d(x:[1 2 3]) ", i))
	}
	q.WriteString("}")

	body := fmt.Sprintf(`{"query":%q}`, q.String())
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected a 1,000-field document with list arguments to forward, got %d (%s)", w.Code, w.Body.String())
	}
	if calls != 1 {
		t.Errorf("expected exactly one upstream call, got %d", calls)
	}
}
