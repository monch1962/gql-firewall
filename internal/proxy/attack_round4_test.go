package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/monch1962/gql-firewall/internal/opa"
	"github.com/monch1962/gql-firewall/internal/parser"
)

// ── R27: HTTP Method Override ─────────────────────────────────────
// Attacker sends POST with X-HTTP-Method-Override: GET to bypass inspection.
func TestAttack_MethodOverride_ShouldStillBeInspected(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { callCount++; w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: false, Reason: "blocked"}})
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(mustJSON(graphQLBody{Query: "{ hello }"})))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-HTTP-Method-Override", "GET")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount != 0 {
		t.Errorf("expected method override to be inspected, upstream called %d times", callCount)
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for blocked request with method override, got %d", w.Code)
	}
}

// ── R28: Content-Type: application/graphql ─────────────────────────
// Attacker sends valid GraphQL with Content-Type: application/graphql
// which is a valid GraphQL content type that bypasses JSON check.
func TestAttack_GraphQLContentType_ShouldBeInspected(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { callCount++; w.WriteHeader(http.StatusOK) })
	defer up.Close()

	// Body is raw GraphQL, not JSON wrapped
	body := `{ hello }`
	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/graphql")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount != 0 {
		t.Errorf("expected application/graphql to be inspected, upstream called %d times", callCount)
	}
	if w.Code != http.StatusUnsupportedMediaType && w.Code != http.StatusBadRequest {
		t.Errorf("expected 4xx for application/graphql, got %d", w.Code)
	}
}

// ── R29: JSON with UTF-8 BOM ──────────────────────────────────────
// Attacker sends JSON body prefixed with UTF-8 BOM (0xEF 0xBB 0xBF).
func TestAttack_JSONWithBOM_ShouldBeInspected(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { callCount++; w.WriteHeader(http.StatusOK) })
	defer up.Close()

	// BOM + valid JSON
	bom := []byte{0xEF, 0xBB, 0xBF}
	jsonBody := `{"query": "{ hello }"}`
	body := append(bom, []byte(jsonBody)...)

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// Should either strip BOM and parse successfully, or reject with 4xx
	// but should NOT forward to upstream without inspection
	if callCount != 0 {
		t.Errorf("expected BOM-prefixed JSON to be inspected, upstream called %d times", callCount)
	}
}

// ── R30: URL-encoded form body ────────────────────────────────────
// Attacker sends query via URL-encoded form instead of JSON.
func TestAttack_URLEncodedBody_ShouldBeRejected(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { callCount++; w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	body := `query={hello}&variables={}`
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount != 0 {
		t.Errorf("expected URL-encoded body to be rejected, upstream called %d times", callCount)
	}
	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415 for URL-encoded body, got %d", w.Code)
	}
}

// ── R31: Anonymous inline fragment ─────────────────────────────────
// Valid GraphQL: { ... { field } } — inline fragment without type condition.
func TestAttack_AnonymousInlineFragment(t *testing.T) {
	q := `{ user { ... { name email } } }`
	info, err := parser.Parse(q)
	if err != nil {
		t.Fatalf("expected anonymous inline fragment to parse, got error: %v", err)
	}
	if info.FieldCount == 0 {
		t.Error("expected fields to be extracted from anonymous inline fragment")
	}
}

// ── R32: Variable as directive argument ────────────────────────────
// Valid GraphQL: query($s: Boolean!) @skip(if: $s) { field }
func TestAttack_VariableAsDirectiveArg(t *testing.T) {
	q := `query($s: Boolean!) @skip(if: $s) { hello }`
	info, err := parser.Parse(q)
	if err != nil {
		t.Fatalf("expected variable-as-directive-arg to parse, got error: %v", err)
	}
	if info.VariableCount != 1 {
		t.Errorf("expected variable_count=1, got %d", info.VariableCount)
	}
	if info.OperationDirectives != 1 {
		t.Errorf("expected operation_directives=1, got %d", info.OperationDirectives)
	}
}

// ── R33: Negative body limit should treat as unlimited (no crash) ──
func TestAttack_NegativeBodyLimit_TreatsAsUnlimited(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { callCount++; w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h, err := New(up.URL, passEval)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h.MaxBodyBytes = -1 // Negative — treat as unlimited (no crash)

	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(mustJSON(graphQLBody{Query: "{ hello }"})))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount != 1 {
		t.Errorf("expected negative body limit to behave as unlimited, upstream called %d times", callCount)
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with negative body limit, got %d", w.Code)
	}
}

// ── R34: Zero body limit allows normal bodies (MaxBytesReader treats 0 as unlimited) ──
func TestAttack_ZeroBodyLimit_AllowsReasonableBodies(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { callCount++; w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h, err := New(up.URL, passEval)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h.MaxBodyBytes = 0 // Zero means no limit (default behavior without MaxBytesReader)

	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(mustJSON(graphQLBody{Query: "{ hello }"})))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount != 1 {
		t.Errorf("expected zero body limit to allow valid request, upstream called %d times", callCount)
	}
}

// ── R35: Very deep fragment chain (not circular) ───────────────────
func TestAttack_DeepFragmentChain_DoesNotOverflow(t *testing.T) {
	// Build a chain of 300 fragments: F0 → F1 → F2 → ... → F299 with numbered names
	var sb strings.Builder
	sb.WriteString("query { ...F0 }")
	for i := 0; i < 300; i++ {
		next := ""
		if i < 299 {
			next = fmt.Sprintf("F%d", i+1)
		}
		if next != "" {
			sb.WriteString(fmt.Sprintf(" fragment F%d on Query { next { ...%s } }", i, next))
		} else {
			sb.WriteString(fmt.Sprintf(" fragment F%d on Query { leaf }", i))
		}
	}
	q := sb.String()

	info, err := parser.Parse(q)
	if err != nil {
		t.Fatalf("expected deep fragment chain to parse, got error: %v", err)
	}
	if info.FragmentCount < 300 {
		t.Errorf("expected fragment_count >= 300, got %d", info.FragmentCount)
	}
}

// ── R36: Batch item with empty query ───────────────────────────────
func TestAttack_BatchItemEmptyQuery_Rejected(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not reach upstream") })
	defer up.Close()

	h := MustNew(up.URL, passEval)

	body := []byte(`[{"operationName":"Test"}]`)
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for batch item with empty query, got %d", w.Code)
	}
}

// ── R37: Duplicate JSON keys in body ───────────────────────────────
func TestAttack_DuplicateJSONKeys_DoesNotCrash(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"ok":true}}`))
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	// JSON with duplicate 'query' key — Go json decoder uses last value
	body := []byte(`{"query": "safe", "query": "{ malicious }"}`)
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code == http.StatusInternalServerError {
		t.Errorf("expected no internal server error for duplicate keys, got %d", w.Code)
	}
	if callCount != 1 {
		t.Errorf("expected forward for duplicate-key JSON, upstream called %d times", callCount)
	}
}

// ── R38: Unicode escapes in JSON body ──────────────────────────────
func TestAttack_UnicodeEscapesInJSON_ShouldParse(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { callCount++; w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	// \u007b = "{", \u007d = "}", so \u007bhello\u007d decodes to {hello}
	body := []byte(`{"query": "\u007bhello\u007d"}`)
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount != 1 {
		t.Errorf("expected unicode-escaped JSON to be inspected, upstream called %d times", callCount)
	}
}

// ── R39: Missing upstream host validation ──────────────────────────
func TestAttack_UpstreamWithoutHost_NewReturnsError(t *testing.T) {
	_, err := New("localhost:8080", passEval)
	if err == nil {
		t.Error("expected error for upstream URL without scheme/host, got nil")
	}
}

// ── R40: Upstream with file scheme should be rejected ──────────────
func TestAttack_UpstreamFileScheme_NewReturnsError(t *testing.T) {
	_, err := New("file:///etc/passwd", passEval)
	if err == nil {
		t.Error("expected error for file:// upstream URL, got nil")
	}
}

// ── R41: Very long operation name ──────────────────────────────────
func TestAttack_VeryLongOperationName_DoesNotCrash(t *testing.T) {
	longName := strings.Repeat("A", 10000)
	q := fmt.Sprintf("query %s { hello }", longName)
	info, err := parser.Parse(q)
	if err != nil {
		t.Fatalf("expected very long operation name to parse, got error: %v", err)
	}
	if len(info.OperationName) != 10000 {
		t.Errorf("expected operation name length 10000, got %d", len(info.OperationName))
	}
}

// ── R42: Comment with special characters ───────────────────────────
func TestAttack_CommentWithSpecialChars_Parses(t *testing.T) {
	q := "{ # unicode arrow: → emoji: 🚀 comment\n hello }"
	info, err := parser.Parse(q)
	if err != nil {
		t.Fatalf("expected comment with special chars to parse, got error: %v", err)
	}
	if info.FieldCount < 1 {
		t.Errorf("expected fields to be extracted despite special chars in comment")
	}
}

// ── R43: Batch with mixed query/mutation types ─────────────────────
func TestAttack_BatchWithMixedTypes_AllInspected(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		body, _ := io.ReadAll(r.Body)
		if !bytes.Contains(body, []byte("mutation")) {
			t.Errorf("expected batch body forwarded upstream to include mutation, got: %s", string(body))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"data":{"ok":true}}]`))
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)

	batch := []map[string]interface{}{
		{"query": "query Q { hello }"},
		{"query": "mutation M { createX }"},
	}
	body, _ := json.Marshal(batch)

	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount != 1 {
		t.Errorf("expected batch with mixed types to forward, upstream called %d times", callCount)
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for allowed mixed batch, got %d", w.Code)
	}
}

// ── R44: Query hash uniqueness ─────────────────────────────────────
func TestAttack_QueryHashesDiffer(t *testing.T) {
	q1, _ := parser.Parse("{ user { name } }")
	q2, _ := parser.Parse("{ posts { title } }")

	if q1.QueryHash == q2.QueryHash {
		t.Error("expected different query hashes for different queries (same depth/fieldCount)")
	}
}

// ── R45: Very deep argument depth ──────────────────────────────────
func TestAttack_DeepArgumentDepth_Measured(t *testing.T) {
	q := `{ search(filter: {a: {b: {c: {d: {e: {f: {g: "deep"}}}}}}}) { result } }`
	info, err := parser.Parse(q)
	if err != nil {
		t.Fatalf("expected deep arg chain to parse, got error: %v", err)
	}
	if info.ArgumentDepth < 6 {
		t.Errorf("expected argument_depth >= 6, got %d", info.ArgumentDepth)
	}
}

// ── R46: Fragment with complex variable definition ─────────────────
func TestAttack_ComplexVariableTypes_Parse(t *testing.T) {
	q := `query($x: [[[String!]!]!]!) { items(data: $x) { id } }`
	info, err := parser.Parse(q)
	if err != nil {
		t.Fatalf("expected complex variable type to parse, got error: %v", err)
	}
	if info.VariableCount != 1 {
		t.Errorf("expected variable_count=1, got %d", info.VariableCount)
	}
}

// ── R47: Very long field path in arguments ─────────────────────────
func TestAttack_VeryLongFieldArgument_DoesNotCrash(t *testing.T) {
	longValue := strings.Repeat("x", 50000)
	q := fmt.Sprintf("{ user(name: %q) { id } }", longValue)
	info, err := parser.Parse(q)
	if err != nil {
		t.Fatalf("expected long string arg to parse, got error: %v", err)
	}
	if info.FieldCount < 2 {
		t.Errorf("expected fields to be extracted despite long arg string")
	}
}
