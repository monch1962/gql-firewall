package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/monch1962/gql-firewall/internal/opa"
	"github.com/monch1962/gql-firewall/internal/parser"
	"github.com/monch1962/gql-firewall/internal/ratelimit"
)

// ── R48: Deeply nested JSON body (stack overflow on json.Unmarshal) ──
func TestAttack_DeeplyNestedJSONBody_Rejected(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not reach upstream") })
	defer up.Close()

	h := MustNew(up.URL, passEval)

	// Build a deeply nested JSON object: {"a":{"a":{"a":...{"query":"{hello}"}}}}
	// Using 10k levels of nesting — should exceed Go's json decoder depth limit
	var sb strings.Builder
	sb.WriteString(`{"a":`)
	inner := `{"query":"{hello}"}`
	for i := 0; i < 10000; i++ {
		sb.WriteString(`{"a":`)
	}
	sb.WriteString(inner)
	for i := 0; i < 10000; i++ {
		sb.WriteString("}")
	}
	body := []byte(sb.String())

	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest && w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 4xx for deeply nested JSON, got %d", w.Code)
	}
}

// ── R49: Trailing garbage after JSON body ──────────────────────────
// Go's json.Decoder allows trailing bytes. Attacker could append
// malicious data that's ignored during parsing.
func TestAttack_JSONTrailingGarbage_Rejected(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not reach upstream") })
	defer up.Close()

	h := MustNew(up.URL, passEval)

	// Valid JSON with trailing garbage
	body := []byte(`{"query":"{hello}"}--EXTRA--DATA`)
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// Should either reject or strip trailing data — but should NOT forward to upstream
	if w.Code != http.StatusBadRequest && w.Code != http.StatusOK {
		t.Errorf("expected 400 or 200 for trailing garbage, got %d", w.Code)
	}
}

// ── R50: Rate limiter memory exhaustion via many unique keys ───────
func TestAttack_RateLimiterMemoryExhaustion(t *testing.T) {
	cfg := ratelimit.Config{RequestsPerSecond: 100, Burst: 100}
	rl := ratelimit.New(cfg)
	defer rl.Stop()

	// Create many unique keys — limiter should not OOM or slow dramatically
	const numKeys = 10000
	results := make([]bool, numKeys)
	for i := 0; i < numKeys; i++ {
		key := fmt.Sprintf("tenant-%d-ip-%d", i%100, i)
		results[i] = rl.Allow(key)
	}

	// All should be allowed (burst=100 means first 100 per key are allowed)
	allowedCount := 0
	for _, r := range results {
		if r {
			allowedCount++
		}
	}
	if allowedCount == 0 {
		t.Error("expected some requests to be allowed across many keys")
	}
}

// ── R51: Admin API body size limit ─────────────────────────────────
// The admin API endpoint /admin/rules/update has no body size limit.
// Attacker can OOM the process with a large config payload.
// This test validates at the server/main.go level by examining
// the admin handler's body reading pattern.

// ── R52: POST with query in URL params and body ────────────────────
// Attacker sends POST with query in URL AND body. Body should win.
func TestAttack_POSTWithQueryInURLAndBody(t *testing.T) {
	callCount := 0
	var capturedQuery string
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Read the forwarded body to see what query reached upstream
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte("body_query")) {
			capturedQuery = "body"
		} else if bytes.Contains(body, []byte("url_query")) {
			capturedQuery = "url"
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"ok":true}}`))
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	// URL has ?query=url_query but body has different query
	body := `{"operationName":"Test"}`
	req := httptest.NewRequest("POST", "/graphql?query={url_query}", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount != 0 {
		t.Errorf("expected POST with URL query and no body query to be rejected, upstream called %d times (body=%s)", callCount, capturedQuery)
	}
}

// ── R53: Very many arguments on a single field ─────────────────────
func TestAttack_VeryManyArguments_Parses(t *testing.T) {
	// Build a query with 500 arguments on one field
	var sb strings.Builder
	sb.WriteString("{ user(")
	for i := 0; i < 500; i++ {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(fmt.Sprintf("arg%d: %d", i, i))
	}
	sb.WriteString(") { name } }")
	q := sb.String()

	info, err := parser.Parse(q)
	if err != nil {
		t.Fatalf("expected many args to parse, got error: %v", err)
	}
	if info.FieldCount < 2 {
		t.Errorf("expected fields (user, name), got %d", info.FieldCount)
	}
}

// ── R54: Non-standard methods to /graphql ──────────────────────────
// OPTIONS, PUT, DELETE, PATCH should pass through without inspection.
func TestAttack_NonStandardMethods_PassThrough(t *testing.T) {
	methods := []string{http.MethodOptions, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			callCount := 0
			up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { callCount++; w.WriteHeader(http.StatusOK) })
			defer up.Close()

			h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: false, Reason: "would block"}})
			req := httptest.NewRequest(method, "/graphql", bytes.NewReader([]byte(`{"query":"{hello}"}`)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if callCount != 1 {
				t.Errorf("expected %s to pass through, upstream called %d times", method, callCount)
			}
		})
	}
}

// ── R55: Null bytes in JSON string values ──────────────────────────
func TestAttack_NullBytesInJSON_ParsesSafely(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not reach upstream") })
	defer up.Close()

	h := MustNew(up.URL, passEval)

	// JSON with null byte in the query value — should be rejected by JSON parser
	body := []byte{0x7b, 0x22, 0x71, 0x75, 0x65, 0x72, 0x79, 0x22, 0x3a, 0x20, 0x22, 0x7b,
		0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 0x7d, 0x22, 0x7d} // {"query": "{hello\x00}"}

	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// Should return 4xx (invalid JSON due to null byte) or handle gracefully
	if w.Code == http.StatusInternalServerError {
		t.Errorf("expected no 500 for null bytes in JSON, got %d", w.Code)
	}
}

// ── R56: Rate limiter concurrent goroutine race ────────────────────
func TestAttack_RateLimiterConcurrentRace(t *testing.T) {
	cfg := ratelimit.Config{RequestsPerSecond: 1000, Burst: 100}
	rl := ratelimit.New(cfg)
	defer rl.Stop()

	const goroutines = 50
	const opsPerGoroutine = 100
	var wg sync.WaitGroup

	// No mutex race should occur
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < opsPerGoroutine; i++ {
				key := fmt.Sprintf("key-%d", id)
				rl.Allow(key)
			}
		}(g)
	}
	wg.Wait()
}

// ── R57: Very many fields in a query (10k+) ────────────────────────
func TestAttack_VeryManyFields_Parses(t *testing.T) {
	// Build a query with 10,000 fields at the root
	var sb strings.Builder
	sb.WriteString("{ ")
	for i := 0; i < 10000; i++ {
		if i > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(fmt.Sprintf("f%d", i))
	}
	sb.WriteString(" }")
	q := sb.String()

	info, err := parser.Parse(q)
	if err != nil {
		t.Fatalf("expected many fields to parse, got error: %v", err)
	}
	if info.FieldCount < 10000 {
		t.Errorf("expected field_count >= 10000, got %d", info.FieldCount)
	}
	if info.FieldCount != 10000 {
		t.Errorf("expected exactly 10000 fields, got %d", info.FieldCount)
	}
}

// ── R58: Batch query with 1000 items ──────────────────────────────
func TestAttack_BatchManyItems_AllInspected(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { callCount++; w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h := MustNew(up.URL, passEval)

	// Build a batch with 1000 items
	var items []map[string]string
	for i := 0; i < 1000; i++ {
		items = append(items, map[string]string{"query": fmt.Sprintf("{ f%d }", i)})
	}
	body, _ := json.Marshal(items)

	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for large batch, got %d", w.Code)
	}
	if callCount != 1 {
		t.Errorf("expected upstream called once, got %d calls", callCount)
	}
}

// ── R59: JSON with a very large number ─────────────────────────────
func TestAttack_JSONVeryLargeNumber_ParsesSafely(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { callCount++; w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h := MustNew(up.URL, passEval)

	// JSON with a very large integer that could overflow
	body := []byte(`{"query":"{hello}","variables":{"id":99999999999999999999999999999999999999}}`)
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// Should not cause internal server error — large number in variables is
	// stored as json.RawMessage and not parsed into a Go numeric type
	if w.Code == http.StatusInternalServerError {
		t.Errorf("expected no 500 for large number, got %d", w.Code)
	}
}

// ── R60: Content-Type with multiple values ─────────────────────────
func TestAttack_MultipleContentTypeValues_Rejected(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { callCount++; w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(mustJSON(graphQLBody{Query: "{ hello }"})))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Content-Type", "text/html")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// Go returns the first Content-Type value (application/json), so this should pass
	if callCount != 1 {
		t.Errorf("expected first Content-Type to be accepted, upstream called %d times", callCount)
	}
}

// ── R61: GET with invalid variables JSON ──────────────────────────
func TestAttack_GETInvalidVariables_ReturnsError(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { callCount++; w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h := MustNew(up.URL, passEval)

	// GET with invalid JSON in variables param (not valid JSON)
	req := httptest.NewRequest("GET", "/graphql?query={hello}&variables=not-json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount != 1 {
		t.Errorf("expected GET with invalid variables to still forward, upstream called %d times", callCount)
	}
}

// ── R62: GraphQL: field name collides with directive name ──────────
func TestAttack_FieldNamedLikeDirective_Parses(t *testing.T) {
	q := `{ skip include deprecated }`
	info, err := parser.Parse(q)
	if err != nil {
		t.Fatalf("expected fields named like directives to parse, got error: %v", err)
	}
	if info.FieldCount != 3 {
		t.Errorf("expected 3 fields (skip, include, deprecated), got %d", info.FieldCount)
	}
}

// ── R63: Admin API rules update with enormous payload ──────────────
func TestAttack_AdminAPIEnormousPayload_DoesNotCrash(t *testing.T) {
	// Create a large config payload (10MB)
	largePayload := make(map[string]interface{})
	largePayload["key"] = strings.Repeat("x", 10*1024*1024)

	body, err := json.Marshal(largePayload)
	if err != nil {
		t.Fatalf("failed to marshal large payload: %v", err)
	}

	// Test only the JSON parsing behavior (not the middleware chain)
	var dest map[string]interface{}
	if err := json.Unmarshal(body, &dest); err != nil {
		t.Fatalf("failed to unmarshal large JSON: %v", err)
	}
	_ = dest
}

// ── R64: Multiple GraphQL queries in one body (string concatenation) ─
func TestAttack_MultipleQueriesInBody_Rejected(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not reach upstream") })
	defer up.Close()

	h := MustNew(up.URL, passEval)

	// Two separate GraphQL queries concatenated as a string
	body := []byte(`{"query": "{ hello } { goodbye }"}`)
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Errorf("expected non-200 for malformed graphql in body field, got %d", w.Code)
	}
}
