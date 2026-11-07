// Package ratelimit provides a simple token-bucket rate limiter
// for per-tenant and per-IP rate limiting.
package ratelimit

import (
	"sync"
	"time"
)

// Config holds rate limiter configuration.
type Config struct {
	RequestsPerSecond float64
	Burst             int
	// MaxKeys caps the number of tracked buckets. Zero applies DefaultMaxKeys;
	// a negative value means unlimited (not recommended).
	MaxKeys int
}

// Limiter implements per-key token-bucket rate limiting.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	config  Config
	stopCh  chan struct{}
}

// DefaultMaxKeys caps the number of tracked buckets so that unauthenticated
// key rotation (forged headers) cannot grow the map without bound.
const DefaultMaxKeys = 100_000

// overflowKey is the shared bucket used once MaxKeys is reached, so that new
// keys are throttled together instead of each receiving a full burst (which
// would make the cap itself a bypass).
const overflowKey = "\x00overflow"

type bucket struct {
	tokens   float64
	lastTick time.Time
}

// New creates a rate limiter that cleans up stale buckets every minute.
func New(cfg Config) *Limiter {
	if cfg.RequestsPerSecond <= 0 {
		cfg.RequestsPerSecond = 100
	}
	if cfg.Burst <= 0 {
		cfg.Burst = 200
	}
	if cfg.MaxKeys == 0 {
		cfg.MaxKeys = DefaultMaxKeys
	}
	l := &Limiter{
		buckets: make(map[string]*bucket),
		config:  cfg,
		stopCh:  make(chan struct{}),
	}
	go l.cleanup()
	return l
}

// Allow checks whether a request from the given key should be allowed.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.bucketFor(key)

	now := time.Now()
	elapsed := now.Sub(b.lastTick).Seconds()
	b.tokens += elapsed * l.config.RequestsPerSecond
	if b.tokens > float64(l.config.Burst) {
		b.tokens = float64(l.config.Burst)
	}
	b.lastTick = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// bucketFor returns the bucket for key, creating it if needed. Once MaxKeys is
// reached, unseen keys share one overflow bucket so the cap cannot be turned
// into a bypass.
func (l *Limiter) bucketFor(key string) *bucket {
	if b, ok := l.buckets[key]; ok {
		return b
	}
	if l.config.MaxKeys > 0 && len(l.buckets) >= l.config.MaxKeys {
		key = overflowKey
		if b, ok := l.buckets[key]; ok {
			return b
		}
	}
	b := &bucket{
		tokens:   float64(l.config.Burst),
		lastTick: time.Now(),
	}
	l.buckets[key] = b
	return b
}

// BucketCount returns the number of tracked buckets.
func (l *Limiter) BucketCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

func (l *Limiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.mu.Lock()
			cutoff := time.Now().Add(-5 * time.Minute)
			for key, b := range l.buckets {
				if b.lastTick.Before(cutoff) {
					delete(l.buckets, key)
				}
			}
			l.mu.Unlock()
		case <-l.stopCh:
			return
		}
	}
}

// Stop cleanly shuts down the cleanup goroutine.
func (l *Limiter) Stop() {
	close(l.stopCh)
}
