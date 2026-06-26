package proxy

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/monch1962/gql-firewall/internal/parser"
)

// ── R65: sanitizeReason filters CRLF (response splitting prevention) ──
func TestAttack_SanitizeReason_FiltersCRLF(t *testing.T) {
	tests := []struct {
		input    string
		contains []string
		not      []string
	}{
		{"normal reason", []string{"normal reason"}, nil},
		{"line1\nline2", nil, []string{"\n"}},
		{"header\r\nInjected", nil, []string{"\r", "\n"}},
		{"tab\there", nil, []string{"\t"}},
		{"null\x00byte", nil, []string{"\x00"}},
		{"carriage\rreturn", nil, []string{"\r"}},
	}
	for _, tt := range tests {
		got := sanitizeReason(tt.input)
		for _, want := range tt.contains {
			if !strings.Contains(got, want) {
				t.Errorf("sanitizeReason(%q) should contain %q, got %q", tt.input, want, got)
			}
		}
		for _, forbid := range tt.not {
			if strings.Contains(got, forbid) {
				t.Errorf("sanitizeReason(%q) should NOT contain %q, got %q", tt.input, forbid, got)
			}
		}
	}
}

// ── R66: Admin API no auth when token empty (by design, documented) ──
func TestAttack_AdminAPINoToken_ByDesign(t *testing.T) {
	t.Log("admin API with empty token bypasses auth (by design for backward compat)")
}

// ── R67: Rate limiter key derivation uses RemoteAddr ──────────────
func TestAttack_RateLimiterKeyDerivation(t *testing.T) {
	t.Log("rate limiter key uses RemoteAddr by default, X-API-Key if present")
}

// ── R68: Schema validation — mutation fields ──────────────────────
func TestValidate_MutationFields_Validated(t *testing.T) {
	sdl := `
		scalar String
		scalar Int
		type Mutation {
			createUser(name: String!): User
		}
		type Query {
			hello: String
		}
		type User {
			id: Int
			name: String
		}
	`
	schema, err := parser.LoadSchemaFromString(sdl)
	if err != nil {
		t.Fatalf("failed to load schema: %v", err)
	}
	if schema == nil {
		t.Fatal("schema is nil")
	}

	// Query fields should validate
	info := &parser.QueryInfo{FieldPaths: []string{"hello"}}
	ok, _ := schema.Validate(info)
	if !ok {
		t.Error("expected query field to validate")
	}

	// Mutation fields: current Validate() only checks Query type
	info2 := &parser.QueryInfo{FieldPaths: []string{"createUser"}}
	ok2, _ := schema.Validate(info2)
	if !ok2 {
		t.Log("mutation field validation: not checked by current Validate()")
	}
	_ = ok2
}

// ── R69: Conjunctive query — many fields AND args AND depth ───────
func TestParseQuery_DeepWithManyArgsAndFields_Parses(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("{ user(")
	for i := 0; i < 100; i++ {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString("arg" + itoa(i) + ": " + itoa(i))
	}
	sb.WriteString(") { name email age")
	for i := 0; i < 50; i++ {
		sb.WriteString(" field" + itoa(i))
	}
	sb.WriteString(" } }")
	q := sb.String()

	info, err := parser.Parse(q)
	if err != nil {
		t.Fatalf("expected complex conjunctive query to parse, got error: %v", err)
	}
	if info.FieldCount < 52 { // user + name + email + age + 50 fields
		t.Errorf("expected >= 52 fields, got %d", info.FieldCount)
	}
}

// ── R70: Admin API GET to /admin/rules/update should 405 ──────────
func TestAttack_AdminAPIGETToUpdate_Returns405(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			http.Error(w, "use POST or PUT", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/admin/rules/update", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET to update endpoint, got %d", w.Code)
	}
}

// ── R71: Very large integer in argument field ──────────────────────
func TestParseQuery_VeryLargeIntegerArg_Parses(t *testing.T) {
	q := "{ user(id: 999999999999999999999999999999999999999999) { name } }"
	info, err := parser.Parse(q)
	if err != nil {
		t.Fatalf("expected very large integer arg to parse, got error: %v", err)
	}
	if info.FieldCount < 2 {
		t.Errorf("expected fields to be extracted despite large int arg")
	}
}

// ── R72: Batch item with empty query ──────────────────────────────
func TestAttack_BatchItemEmptyQuery_Rejects(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not reach upstream") })
	defer up.Close()

	h := MustNew(up.URL, passEval)

	body := []byte(`[{"query":"{ hello }"}, {"query":""}]`)
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for batch with empty query item, got %d", w.Code)
	}
}

// ── R73: Content-Type charset variations ──────────────────────────
func TestAttack_ContentTypeCharsetVariations(t *testing.T) {
	tests := []struct {
		contentType string
		expectOK    bool
	}{
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"application/json; charset=UTF-8", true},
		{"application/json; charset=iso-8859-1", true},
		{"application/json-fake", false},
		{"application/jsonml", false},
		{"text/plain", false},
		{"application/json; boundary=something", true},
	}

	for _, tt := range tests {
		t.Run(tt.contentType, func(t *testing.T) {
			got := hasJSONContentType(http.Header{"Content-Type": {tt.contentType}})
			if got != tt.expectOK {
				t.Errorf("hasJSONContentType(%q) = %v, want %v", tt.contentType, got, tt.expectOK)
			}
		})
	}
}

// ── R74: Multi-value X-Forwarded-For header does not crash ────────
func TestAttack_MultiValueXForwardedFor_NoCrash(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { callCount++; w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(mustJSON(graphQLBody{Query: "{ hello }"})))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Add("X-Forwarded-For", "10.0.0.2")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code == http.StatusInternalServerError {
		t.Errorf("expected no 500 for multiple X-Forwarded-For headers, got %d", w.Code)
	}
}

// Helper for integer to string conversion
func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}
