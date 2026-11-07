package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/monch1962/gql-firewall/internal/opa"
	"github.com/monch1962/gql-firewall/internal/parser"
)

// captureEval records the QueryInfo handed to the evaluator so tests can assert
// what the firewall actually inspected before forwarding.
type captureEval struct {
	calls []*parser.QueryInfo
	block bool
}

func (c *captureEval) Evaluate(info *parser.QueryInfo) (*opa.Result, error) {
	c.calls = append(c.calls, info)
	if c.block {
		return &opa.Result{Allowed: false, Reason: "blocked by test"}, nil
	}
	return &opa.Result{Allowed: true}, nil
}

// ── R83: Batch envelope drops tenant identity ────────────────────────────────
// Not in CAPEC: inspection/execution mismatch — the batch code path evaluates
// each item without the X-API-Key tenant that the single-request path applies,
// so wrapping a query in a JSON array sidesteps every per-tenant rule.
func TestAttack_BatchBypassesTenantResolution(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	defer up.Close()

	ev := &captureEval{}
	h := MustNew(up.URL, ev)

	body, err := json.Marshal([]graphQLBody{{Query: "{ hello }"}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "acme_s3cr3t")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if len(ev.calls) != 1 {
		t.Fatalf("expected exactly 1 evaluation, got %d", len(ev.calls))
	}
	if got := ev.calls[0].TenantID; got != "acme" {
		t.Errorf("batch request lost tenant identity: got %q, want %q — per-tenant policy is bypassed by the batch envelope", got, "acme")
	}
}

// ── R91: Path normalisation mismatch ────────────────────────────────────────
// CAPEC-274 adjacent: the same endpoint is reached under several spellings;
// the firewall inspects only the exact "/graphql" suffix and forwards every
// other spelling uninspected, while prefix-mounting servers still execute it.
func TestAttack_TrailingSlashPathBypass(t *testing.T) {
	for _, path := range []string{"/graphql/", "/graphql//", "/GraphQL/", "/api/graphql/", "/graphql/."} {
		t.Run(path, func(t *testing.T) {
			upstreamCalls := 0
			up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls++
				w.WriteHeader(http.StatusOK)
			})
			defer up.Close()

			h := MustNew(up.URL, &captureEval{block: true})
			req := httptest.NewRequest("POST", path, gql("{ hello }"))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("%s: expected the blocked query to be inspected and rejected (403), got %d", path, w.Code)
			}
			if upstreamCalls != 0 {
				t.Errorf("%s: blocked query reached upstream %d time(s) — firewall bypassed", path, upstreamCalls)
			}
		})
	}
}

// ── R92: Unbounded batch size ───────────────────────────────────────────────
// Not in CAPEC: resource exhaustion — every array element is parsed and
// evaluated, so one 1MB body can force ~25k independent parse+evaluate cycles.
func TestAttack_BatchSizeUnbounded(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	defer up.Close()

	ev := &captureEval{}
	h := MustNew(up.URL, ev)

	items := make([]graphQLBody, 101)
	for i := range items {
		items[i].Query = "{ hello }"
	}
	body, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected oversized batch to be rejected (400), got %d", w.Code)
	}
	if len(ev.calls) != 0 {
		t.Errorf("oversized batch was partially evaluated (%d calls) before rejection", len(ev.calls))
	}
}

// ── R93: Unbounded parse concurrency ────────────────────────────────────────
// Not in CAPEC: DoS via goroutine growth — parseQueryWithTimeout abandons the
// wait on timeout but the goroutine keeps burning CPU, and nothing caps how
// many parses run at once.
func TestAttack_ParseConcurrencyUnbounded(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	// Simulate a saturated parse pool: every slot is occupied by an in-flight
	// (attacker-supplied, expensive) query.
	h.parseSem = make(chan struct{}, 1)
	h.parseSem <- struct{}{}

	req := httptest.NewRequest("POST", "/graphql", gql("{ hello }"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when the parse pool is saturated, got %d — parse concurrency is unbounded", w.Code)
	}
}
