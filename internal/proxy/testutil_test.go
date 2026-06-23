// Shared test helpers for the proxy package.
package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mustJSON marshals v to JSON, panicking on error.
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// testUpstream creates an HTTP test server that acts as a stub upstream.
func testUpstream(t *testing.T, handler func(http.ResponseWriter, *http.Request)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(handler))
}
