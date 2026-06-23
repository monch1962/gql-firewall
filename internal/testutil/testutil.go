// Package testutil provides shared test helpers for gql-firewall tests.
package testutil

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// MustJSON marshals v to JSON, panicking on error.
func MustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// TestUpstream creates an HTTP test server that acts as a stub upstream.
func TestUpstream(t *testing.T, handler func(http.ResponseWriter, *http.Request)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(handler))
}

// PostGraphQL sends a POST /graphql with the given query and optional headers.
func PostGraphQL(t *testing.T, baseURL, query string, headers ...string) *http.Response {
	t.Helper()
	body := map[string]string{"query": query}
	data, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", baseURL+"/graphql", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return resp
}

// ReadBody reads the full response body and closes it.
func ReadBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return string(data)
}
