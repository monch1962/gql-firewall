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
}

// Limiter implements per-key token-bucket rate limiting.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	config  Config
	stopCh  chan struct{}
}

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

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{
			tokens:   float64(l.config.Burst),
			lastTick: time.Now(),
		}
		l.buckets[key] = b
	}

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
