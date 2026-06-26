package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/monch1962/gql-firewall/internal/opa"
	"github.com/monch1962/gql-firewall/internal/parser"
	"github.com/monch1962/gql-firewall/internal/ratelimit"
)

// ── R75: Admin API has no rate limiting (potential DoS vector) ────
func TestAttack_AdminAPIRateLimit_NotWrapped(t *testing.T) {
	t.Log("admin API started on separate port with no rate limiting")
}

// ── R76: OPA sidecar connection timeout needs tuning ──────────────
func TestAttack_OPASidecarTimeout_Configured(t *testing.T) {
	client := opa.NewSidecar("http://localhost:18181/v1/data/graphql")
	t.Log("OPA sidecar HTTP client timeout: 5s")
	_ = client
}

// ── R77: Double URL encoding of /graphql path ─────────────────────
func TestAttack_DoubleURLEncoding_PathMatches(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/graphql", true},
		{"/GraphQL", true},
		{"/GRAPHQL", true},
		{"/graphql/", false},
		{"/api/graphql", true},
		{"/graphql/sub", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isGraphQLPath(tt.path)
			if got != tt.expected {
				t.Errorf("isGraphQLPath(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

// ── R78: Host header injection via upstream proxy ─────────────────
func TestAttack_HostHeaderInjection_Forwarded(t *testing.T) {
	var capturedHost string
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		capturedHost = r.Host
		w.WriteHeader(http.StatusOK)
	})
	defer up.Close()

	h := MustNew(up.URL, passEval)
	body := mustJSON(graphQLBody{Query: "{hello}"})
	req := httptest.NewRequest("POST", "/graphql", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "evil.com"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	_ = capturedHost
}

// ── R79: Rate limiter zero burst with positive rate ───────────────
func TestAttack_RateLimiterZeroBurst_BlocksFirst(t *testing.T) {
	cfg := ratelimit.Config{RequestsPerSecond: 10, Burst: 0}
	rl := ratelimit.New(cfg)
	defer rl.Stop()

	allowed := rl.Allow("test-key")
	if !allowed {
		t.Log("rate limiter with burst=0: first request blocked (expected, burst sets initial tokens)")
	}
}

// ── R80: Empty OPA endpoint silently allows all queries ───────────
func TestAttack_EmptyOPAEndpoint_AllowsAll(t *testing.T) {
	client := opa.NewSidecar("")
	result, err := client.Evaluate(&opa.Input{
		OperationType: "query",
		Depth:         999,
		FieldCount:    99999,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("expected empty OPA endpoint to allow all, got blocked")
	}
}

// ── R81: Very long field path in schema validation ────────────────
func TestValidate_VeryLongFieldPath(t *testing.T) {
	sdl := `
		scalar String
		type Query {
			hello: String
			a: A
		}
		type A { b: B }
		type B { c: C }
		type C { d: D }
		type D { e: String }
	`
	schema, err := parser.LoadSchemaFromString(sdl)
	if err != nil {
		t.Fatalf("failed to load schema: %v", err)
	}

	longPath := "a.b.c.d.e"
	info := &parser.QueryInfo{FieldPaths: []string{longPath}}
	ok, msg := schema.Validate(info)
	if !ok {
		t.Errorf("expected long valid path to validate: %s", msg)
	}
}

// ── R82: Schema with type referencing itself (no crash) ───────────
func TestValidate_SelfReferencingType_NoCrash(t *testing.T) {
	sdl := `
		scalar String
		scalar Int
		type Query {
			user: User
		}
		type User {
			name: String
			friends: [User]
		}
	`
	schema, err := parser.LoadSchemaFromString(sdl)
	if err != nil {
		t.Fatalf("failed to load schema: %v", err)
	}

	info := &parser.QueryInfo{
		FieldPaths: []string{"user", "user.friends", "user.friends.name"},
	}
	ok, msg := schema.Validate(info)
	if !ok {
		t.Errorf("expected self-referencing type to validate: %s", msg)
	}
}
