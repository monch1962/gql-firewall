package ratelimit

import (
	"fmt"
	"testing"
)

// ── R89: Unbounded per-key bucket growth ────────────────────────────────────
// Not in CAPEC: memory exhaustion. Buckets are only reaped once a minute and
// only after 5 minutes of idleness, so an attacker rotating keys (via a
// forged header) can grow the map without bound.
func TestAttack_RateLimiterUnboundedBuckets(t *testing.T) {
	l := New(Config{RequestsPerSecond: 1, Burst: 1, MaxKeys: 10})
	defer l.Stop()

	for i := 0; i < 1000; i++ {
		l.Allow(fmt.Sprintf("attacker-key-%d", i))
	}

	if got := l.BucketCount(); got > 11 {
		t.Errorf("bucket map grew to %d entries with MaxKeys=10 — unbounded memory (DoS)", got)
	}

	// Once the cap is reached, brand-new keys must not each get a full burst:
	// they share the overflow bucket and are therefore throttled.
	allowed := 0
	for i := 0; i < 100; i++ {
		if l.Allow(fmt.Sprintf("fresh-key-%d", i)) {
			allowed++
		}
	}
	if allowed > 3 {
		t.Errorf("%d of 100 fresh keys were allowed past the cap — each new key still minted an independent bucket", allowed)
	}
}
