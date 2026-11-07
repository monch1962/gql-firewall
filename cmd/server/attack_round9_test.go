package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/monch1962/gql-firewall/internal/parser"
)

// withSource sets the identity source on a QueryInfo.
func withSource(s string) func(*parser.QueryInfo) {
	return func(i *parser.QueryInfo) { i.TenantIdentitySource = s }
}

// withCacheMaxEntries bounds the decision cache.
func withCacheMaxEntries(n int) func(*compositeEvaluator) {
	return func(e *compositeEvaluator) { e.maxCacheSize = n }
}

// withAllowUnknownTenants opts out of unknown-tenant rejection.
func withAllowUnknownTenants() func(*compositeEvaluator) {
	return func(e *compositeEvaluator) { e.allowUnknownTenants = true }
}

// ── R95: claimed-but-unregistered tenant is rejected ───────────────────────
// CAPEC-21: exploitation of trusted identifiers. Before this change an unknown
// tenant ID silently fell through to the global parameter set, so any client
// could choose which configuration set its request was measured against.
func TestAttack_UnregisteredTenantDenied(t *testing.T) {
	e := newEval(withTenantParams("acme", map[string]interface{}{"depth_limit": 3.0}))

	r, err := e.Evaluate(qi(tenantID("evil"), paths("hello")))
	assertBlock(t, r, err, "unknown tenant")
}

func TestAttack_RegisteredTenantAllowed(t *testing.T) {
	e := newEval(withTenantParams("acme", map[string]interface{}{"depth_limit": 3.0}))

	r, err := e.Evaluate(qi(tenantID("acme"), withSource("header"), paths("hello")))
	assertAllow(t, r, err)
}

// Single-tenant deployments register no tenants, so the behaviour must be
// unchanged: there is nothing for a claimed ID to be unknown against.
func TestAttack_NoTenantsRegistered_UnknownClaimAllowed(t *testing.T) {
	r, err := newEval().Evaluate(qi(tenantID("anything"), paths("hello")))
	assertAllow(t, r, err)
}

// Anonymous traffic is not an unknown claim; it is evaluated against the
// global parameter set (use a policy knob to require credentials).
func TestAttack_AbsentTenantIsAnonymous(t *testing.T) {
	e := newEval(withTenantParams("acme", map[string]interface{}{"depth_limit": 3.0}))

	r, err := e.Evaluate(qi(paths("hello")))
	assertAllow(t, r, err)
}

func TestAttack_AllowUnknownTenantsOptOut(t *testing.T) {
	e := newEval(
		withTenantParams("acme", map[string]interface{}{"depth_limit": 3.0}),
		withAllowUnknownTenants(),
	)

	r, err := e.Evaluate(qi(tenantID("evil"), paths("hello")))
	assertAllow(t, r, err)
}

// ── R95: decision cache is bounded ─────────────────────────────────────────
// Tenant identity is attacker-influenced and now part of the cache key, so an
// unbounded cache turns identity spoofing into unbounded memory growth.
func TestAttack_DecisionCacheBounded(t *testing.T) {
	e := newEval(withCacheTTL(time.Minute), withCacheMaxEntries(10))

	for i := 0; i < 100; i++ {
		if _, err := e.Evaluate(qi(tenantID(fmt.Sprintf("tenant-%d", i)), paths("hello"))); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if got := len(e.cache); got > 10 {
		t.Errorf("decision cache grew to %d entries with a limit of 10 — unbounded memory", got)
	}
}

// Expired entries must be reclaimed at the limit, not only when the TTL is read.
func TestAttack_DecisionCacheExpiredSwept(t *testing.T) {
	e := newEval(withCacheTTL(time.Millisecond), withCacheMaxEntries(2))

	e.Evaluate(qi(paths("a")))
	e.Evaluate(qi(paths("b")))
	if got := len(e.cache); got != 2 {
		t.Fatalf("expected 2 cached entries, got %d", got)
	}

	time.Sleep(5 * time.Millisecond)
	e.Evaluate(qi(paths("c")))

	if got := len(e.cache); got != 1 {
		t.Errorf("expected expired entries to be swept (1 live entry), got %d", got)
	}
}

// A policy can branch on identity source, so the cache must too.
func TestAttack_CacheKeyIncludesIdentitySource(t *testing.T) {
	if decisionCacheKey(qi(withSource("header"))) == decisionCacheKey(qi(withSource("hmac"))) {
		t.Error("cache key ignores tenant identity source: a header-mode decision would be replayed for a verified caller")
	}
}
