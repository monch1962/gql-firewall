// Shared test helpers for the proxy package.
package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// nestedQuery builds `{a{a{…b…}}}` with the requested selection depth — the
// payload shape used by the nesting-bomb attacks. Depth n costs ~3n bytes.
func nestedQuery(depth int) string {
	var b strings.Builder
	b.Grow(depth*3 + 8)
	b.WriteString("{")
	for i := 0; i < depth; i++ {
		b.WriteString("a{")
	}
	b.WriteString("b")
	for i := 0; i <= depth; i++ {
		b.WriteString("}")
	}
	return b.String()
}
