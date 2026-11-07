package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/monch1962/gql-firewall/internal/metrics"
	"github.com/monch1962/gql-firewall/internal/opa"
	"github.com/monch1962/gql-firewall/internal/parser"
	"github.com/monch1962/gql-firewall/internal/ratelimit"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// withVars sets the raw request variables on a QueryInfo.
func withVars(js string) func(*parser.QueryInfo) {
	return func(i *parser.QueryInfo) { i.RequestVariables = json.RawMessage(js) }
}

// policyEnforcingStub blocks on tenant identity and on a request variable, and
// counts how many times the real policy engine was consulted.
type policyEnforcingStub struct{ calls int }

func (e *policyEnforcingStub) Evaluate(in *opa.Input) (*opa.Result, error) {
	e.calls++
	if in.TenantID == "restricted" {
		return &opa.Result{Allowed: false, Reason: "tenant blocked"}, nil
	}
	if role, ok := in.RequestVariables["role"]; ok && role == "admin" {
		return &opa.Result{Allowed: false, Reason: "role blocked"}, nil
	}
	return &opa.Result{Allowed: true}, nil
}

func (e *policyEnforcingStub) Configured() bool { return true }

// ── R84: Decision cache bleeds across tenants ───────────────────────────────
// Not in CAPEC: cache poisoning. The cache key omits tenant_id, so a decision
// obtained for a permissive tenant is replayed for a restricted one.
func TestAttack_DecisionCacheCrossTenantBleed(t *testing.T) {
	stub := &policyEnforcingStub{}
	e := newEval(withCacheTTL(time.Minute))
	e.opa = stub

	r1, err := e.Evaluate(qi(paths("user.name"), tenantID("public")))
	assertAllow(t, r1, err)

	r2, err := e.Evaluate(qi(paths("user.name"), tenantID("restricted")))
	if stub.calls != 2 {
		t.Errorf("policy consulted %d time(s), want 2 — the cached decision was replayed across tenants", stub.calls)
	}
	assertBlock(t, r2, err, "tenant blocked")
}

// ── R84b: Decision cache bleeds across variable payloads ────────────────────
func TestAttack_DecisionCacheCrossVariableBleed(t *testing.T) {
	stub := &policyEnforcingStub{}
	e := newEval(withCacheTTL(time.Minute))
	e.opa = stub

	r1, err := e.Evaluate(qi(paths("user.name"), withVars(`{"role":"user"}`)))
	assertAllow(t, r1, err)

	r2, err := e.Evaluate(qi(paths("user.name"), withVars(`{"role":"admin"}`)))
	if stub.calls != 2 {
		t.Errorf("policy consulted %d time(s), want 2 — request variables are absent from the cache key", stub.calls)
	}
	assertBlock(t, r2, err, "role blocked")
}

// blockingPathStub blocks any query that touches a specific field path.
type blockingPathStub struct {
	blocked string
	calls   int
}

func (e *blockingPathStub) Evaluate(in *opa.Input) (*opa.Result, error) {
	e.calls++
	for _, p := range in.FieldPaths {
		if p == e.blocked {
			return &opa.Result{Allowed: false, Reason: "path blocked"}, nil
		}
	}
	return &opa.Result{Allowed: true}, nil
}

func (e *blockingPathStub) Configured() bool { return true }

// ── R85: Ambiguous field-path encoding → cache poisoning ────────────────────
// ["x.y","z"] and ["x.yz"] both concatenate to "x.yz", and both report the
// same depth/field_count, so they share a cache key: an allowed query poisons
// the entry for a query that touches a blocked field.
func TestAttack_CachePoisoningViaPathAmbiguity(t *testing.T) {
	a := qi(paths("x.y", "z"), depth(2), fieldCount(2))
	b := qi(paths("x.yz"), depth(2), fieldCount(2))
	if decisionCacheKey(a) == decisionCacheKey(b) {
		t.Fatalf("field-path encoding is ambiguous: [x.y z] and [x.yz] share cache key %q", decisionCacheKey(a))
	}

	// End-to-end: prime the cache with the allowed spelling, then request the
	// blocked field. The second request must be decided by the policy engine.
	stub := &blockingPathStub{blocked: "z"}
	e := newEval(withCacheTTL(time.Minute))
	e.opa = stub

	r1, err := e.Evaluate(qi(paths("x.yz"), depth(2), fieldCount(2)))
	assertAllow(t, r1, err)

	r2, err := e.Evaluate(qi(paths("x.y", "z"), depth(2), fieldCount(2)))
	if stub.calls != 2 {
		t.Errorf("policy consulted %d time(s), want 2 — poisoned cache entry bypassed the block", stub.calls)
	}
	assertBlock(t, r2, err, "path blocked")
}

// ── R86: Attacker-controlled metric label (cardinality bomb) ────────────────
// Schema validation messages embed the requested field name, and that message
// is used as a Prometheus label, so every unique bogus field name creates a
// permanent new time series.
func TestAttack_BlockReasonMetricCardinalityBomb(t *testing.T) {
	l1 := metrics.ReasonLabel(`field "attacker_one" does not exist on type "Query"`)
	l2 := metrics.ReasonLabel(`field "attacker_two" does not exist on type "Query"`)
	if l1 != l2 {
		t.Errorf("block reason label is attacker-controlled: %q vs %q", l1, l2)
	}
	if strings.Contains(l1, "attacker") {
		t.Errorf("metric label leaks attacker-supplied text: %q", l1)
	}

	schema, err := parser.LoadSchemaFromString("type Query { hello: String }\nscalar String\n")
	if err != nil {
		t.Fatal(err)
	}
	e := newEval(withSchema(schema))
	before := testutil.CollectAndCount(metrics.RequestsBlocked)
	e.Evaluate(qi(paths("no_such_field_a")))
	e.Evaluate(qi(paths("no_such_field_b")))
	after := testutil.CollectAndCount(metrics.RequestsBlocked)
	if delta := after - before; delta > 1 {
		t.Errorf("2 requests created %d new metric series — unbounded label cardinality (memory DoS)", delta)
	}
}

// ── R87: Admin API bindable to the network without a token ──────────────────
// Not in CAPEC: insecure default. `-admin` defaults to all interfaces and an
// empty token disables auth, exposing rule rewrite (and therefore every
// bypass) to anyone who can reach the port.
func TestAttack_AdminExposedWithoutToken(t *testing.T) {
	cases := []struct {
		addr, token string
		wantErr     bool
	}{
		{"0.0.0.0:8082", "", true},
		{":8082", "", true},
		{"192.0.2.5:8082", "", true},
		{"127.0.0.1:8082", "", false},
		{"localhost:8082", "", false},
		{"[::1]:8082", "", false},
		{"0.0.0.0:8082", "secret", false},
		{"", "", false}, // admin API disabled
	}
	for _, c := range cases {
		err := validateAdminBind(c.addr, c.token)
		if (err != nil) != c.wantErr {
			t.Errorf("validateAdminBind(%q, token=%q) error = %v, wantErr %v", c.addr, c.token, err, c.wantErr)
		}
	}
}

// ── R88: Rate limiting keyed on client-supplied headers ─────────────────────
// Not in CAPEC: throttling bypass. Rotating X-API-Key (or a spoofed
// X-Forwarded-For) mints a fresh bucket per request, so the limit never trips.
func TestAttack_RateLimitBypassViaHeaderRotation(t *testing.T) {
	run := func(t *testing.T, mutate func(*http.Request, int)) []int {
		t.Helper()
		rl := ratelimit.New(ratelimit.Config{RequestsPerSecond: 1, Burst: 1})
		defer rl.Stop()
		h := rateLimitMiddleware(rl, http.HandlerFunc(okHandler))

		var codes []int
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("POST", "/graphql", nil)
			req.RemoteAddr = "192.0.2.10:5555" // same socket address every time
			mutate(req, i)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			codes = append(codes, w.Code)
		}
		return codes
	}

	t.Run("rotating X-API-Key", func(t *testing.T) {
		codes := run(t, func(r *http.Request, i int) {
			r.Header.Set("X-API-Key", fmt.Sprintf("rotating-key-%d", i))
		})
		for i := 1; i < len(codes); i++ {
			if codes[i] != http.StatusTooManyRequests {
				t.Errorf("request %d got %d, want 429 — unverified API keys must not mint new buckets (codes=%v)", i, codes[i], codes)
			}
		}
	})

	t.Run("rotating X-Forwarded-For", func(t *testing.T) {
		codes := run(t, func(r *http.Request, i int) {
			r.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.0.%d", i))
		})
		for i := 1; i < len(codes); i++ {
			if codes[i] != http.StatusTooManyRequests {
				t.Errorf("request %d got %d, want 429 — XFF must not be trusted unless explicitly enabled (codes=%v)", i, codes[i], codes)
			}
		}
	})
}

// ── R94: Fail-open is the default when OPA is unreachable ───────────────────
// Not in CAPEC: security-control bypass by availability. If OPA is down or
// slow, every request is allowed, so DoSing the policy engine disables the
// firewall.
func TestAttack_OPAFailOpenIsNotDefault(t *testing.T) {
	if !defaultOPAFailClosed {
		t.Error("request evaluation fails open by default: an OPA outage silently disables every rule")
	}
}
