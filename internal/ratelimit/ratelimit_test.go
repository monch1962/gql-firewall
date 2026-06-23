package ratelimit

import (
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	l := New(Config{RequestsPerSecond: 10, Burst: 20})
	defer l.Stop()
	if l == nil {
		t.Fatal("expected non-nil limiter")
	}
}

func TestAllow_WithinBurst(t *testing.T) {
	l := New(Config{RequestsPerSecond: 100, Burst: 10})
	defer l.Stop()
	for i := 0; i < 10; i++ {
		if !l.Allow("test") {
			t.Errorf("expected allow for request %d within burst", i+1)
		}
	}
}

func TestAllow_ExceedsBurst(t *testing.T) {
	l := New(Config{RequestsPerSecond: 100, Burst: 5})
	defer l.Stop()
	for i := 0; i < 5; i++ {
		l.Allow("test")
	}
	if l.Allow("test") {
		t.Error("expected deny after burst exceeded")
	}
}

func TestAllow_DifferentKeysIndependent(t *testing.T) {
	l := New(Config{RequestsPerSecond: 100, Burst: 3})
	defer l.Stop()
	for i := 0; i < 3; i++ {
		l.Allow("tenant_a")
	}
	if !l.Allow("tenant_b") {
		t.Error("expected tenant_b to have its own burst budget")
	}
	if l.Allow("tenant_a") {
		t.Error("expected tenant_a denied after exceeding burst")
	}
}

func TestAllow_RefillsOverTime(t *testing.T) {
	l := New(Config{RequestsPerSecond: 100, Burst: 1})
	defer l.Stop()
	l.Allow("test")
	if l.Allow("test") {
		t.Error("expected deny immediately after burst")
	}
	time.Sleep(15 * time.Millisecond)
	if !l.Allow("test") {
		t.Error("expected allow after refill")
	}
}

func TestConcurrentAccess(t *testing.T) {
	l := New(Config{RequestsPerSecond: 1000, Burst: 100})
	defer l.Stop()
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 10; j++ {
				l.Allow("concurrent")
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}
