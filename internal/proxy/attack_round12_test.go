package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/monch1962/gql-firewall/internal/opa"
	"github.com/monch1962/gql-firewall/internal/parser"
)

// ── R98: nesting bomb must be stopped before policy evaluation ─────────────
// The firewall's depth/cost rules only see an operation after the parser has
// walked it. A 300KB body of `{a{a{…` burned 4.8s of CPU on gqlparser
// v2.5.34 and ~900KB got the sidecar OOM-killed, so the request never reached
// Rego at all. The fix bounds nesting inside the parser; the handler must then
// answer 400 without touching the upstream or the policy engine.
//
// CAPEC-130: Excessive Allocation.
func TestAttack_NestingBombRejectedBeforePolicy(t *testing.T) {
	upstreamCalls := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	evalCalls := 0
	ev := &countingEvaluator{calls: &evalCalls}

	h := MustNew(up.URL, ev)
	h.ParseTimeout = 5 * time.Second

	const depth = 5000
	body := mustJSON(map[string]string{"query": nestedQuery(depth)})

	req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	start := time.Now()
	h.ServeHTTP(w, req)
	elapsed := time.Since(start)

	if w.Code != http.StatusBadRequest && w.Code != http.StatusForbidden {
		t.Errorf("expected 400/403 for nesting bomb, got %d (body=%s)", w.Code, w.Body.String())
	}
	if upstreamCalls != 0 {
		t.Errorf("upstream called %d times for a rejected nesting bomb", upstreamCalls)
	}
	if evalCalls != 0 {
		t.Errorf("policy evaluated %d times for a rejected nesting bomb, want 0", evalCalls)
	}
	if elapsed > 2*time.Second {
		t.Errorf("rejection took %s, want < 2s", elapsed)
	}
	// The response must stay well-formed JSON (no panic / partial write).
	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Errorf("response is not valid JSON: %v (%q)", err, w.Body.String())
	}
}

// countingEvaluator records how often policy evaluation runs.
type countingEvaluator struct {
	calls *int
	res   *opa.Result
}

func (c *countingEvaluator) Evaluate(_ *parser.QueryInfo) (*opa.Result, error) {
	*c.calls++
	if c.res != nil {
		return c.res, nil
	}
	return &opa.Result{Allowed: true}, nil
}
