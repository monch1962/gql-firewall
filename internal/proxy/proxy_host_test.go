package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// ──────────────────────────────────────────────────────────
// Direct tests for newHostFixedReverseProxy
// Ensures the Host header is pinned to the upstream target,
// preventing Host header injection (CAPEC-664).
// ──────────────────────────────────────────────────────────

func TestNewHostFixedProxy_PinsHostHeader(t *testing.T) {
	var capturedHost string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()

	upURL, _ := url.Parse(up.URL)
	proxy := newHostFixedReverseProxy(upURL)

	// Create a request with a malicious Host header
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "evil-internal:8080"
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if capturedHost == "evil-internal:8080" {
		t.Errorf("newHostFixedReverseProxy: Host header was not pinned — upstream saw %q", capturedHost)
	}
	if capturedHost != upURL.Host {
		t.Errorf("newHostFixedReverseProxy: expected Host to be %q, got %q", upURL.Host, capturedHost)
	}
}

func TestNewHostFixedProxy_PreservesNormalHost(t *testing.T) {
	var capturedHost string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()

	upURL, _ := url.Parse(up.URL)
	proxy := newHostFixedReverseProxy(upURL)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if capturedHost != upURL.Host {
		t.Errorf("newHostFixedReverseProxy: expected normal Host %q, got %q", upURL.Host, capturedHost)
	}
}

func TestNewHostFixedProxy_ForwardsRequest(t *testing.T) {
	var pathHit string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathHit = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()

	upURL, _ := url.Parse(up.URL)
	proxy := newHostFixedReverseProxy(upURL)

	req := httptest.NewRequest("POST", "/graphql", nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("newHostFixedReverseProxy: expected 200, got %d", w.Code)
	}
	if pathHit != "/graphql" {
		t.Errorf("newHostFixedReverseProxy: expected path /graphql, got %q", pathHit)
	}
}
