package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── R102: value-node bomb over the wire ────────────────────────────────────
// The node budget must charge string literals as AST nodes. Before R102 a
// 390KB body of `{a(x:["s" "s" …])}` was admitted — it is inside the 1MB body
// limit, depth 1, and the scan reported 2 nodes — and the parse then allocated
// ~24.5MB. A batch envelope multiplies it, so both paths are asserted here.
//
// CAPEC-130: Excessive Allocation.
func stringBombQuery(n int) string {
	var b strings.Builder
	b.WriteString(`{a(x:[`)
	for i := 0; i < n; i++ {
		b.WriteString(`"s" `)
	}
	b.WriteString(`])}`)
	return b.String()
}

func TestAttack_StringValueBombRejectedAtHTTP(t *testing.T) {
	calls := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	body := fmt.Sprintf(`{"query":%q}`, stringBombQuery(100_000))
	if len(body) > 1024*1024 {
		t.Fatalf("payload %d bytes exceeds the default body limit — test is not exercising the budget", len(body))
	}

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	start := time.Now()
	h.ServeHTTP(w, req)
	elapsed := time.Since(start)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for value-node bomb, got %d (%s)", w.Code, w.Body.String())
	}
	if calls != 0 {
		t.Errorf("upstream called %d times for a rejected document", calls)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("rejection took %s — the budget did not run before the parse", elapsed)
	}
}

// CAPEC-130: the array envelope gives every item its own document budget, so a
// batch of value bombs must be rejected per item, not parsed 100 times.
func TestAttack_StringValueBombRejectedInBatch(t *testing.T) {
	calls := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	item := fmt.Sprintf(`{"query":%q}`, stringBombQuery(11_000))
	body := "[" + strings.Repeat(item+",", 7) + item + "]"
	if len(body) > 1024*1024 {
		t.Fatalf("batch payload %d bytes exceeds the body limit", len(body))
	}

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for batch of value bombs, got %d (%s)", w.Code, w.Body.String())
	}
	if calls != 0 {
		t.Errorf("upstream called %d times for a rejected batch", calls)
	}
}

// CAPEC-130: the mirror image — a single large string argument is one node and
// must still be forwarded. Charging literal *bytes* would be a self-inflicted
// denial of service against legitimate traffic.
func TestAttack_LargeStringArgumentStillForwarded(t *testing.T) {
	calls := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	var s strings.Builder
	for s.Len() < 400_000 {
		s.WriteString("someText ")
	}
	body := fmt.Sprintf(`{"query":%q}`, `{a(s:"`+s.String()+`")}`)

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("legitimate large string argument rejected with %d (%s)", w.Code, w.Body.String())
	}
	if calls != 1 {
		t.Errorf("expected upstream to be called once, got %d", calls)
	}
}
