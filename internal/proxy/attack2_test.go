package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/monch1962/gql-firewall/internal/rules"
	"github.com/monch1962/gql-firewall/internal/tenant"
)

// R15: Tenant ID extraction edge cases
func TestAttack_TenantIDFringeCases(t *testing.T) {
	tests := []struct{ key, want string }{
		{"tenant_secret", "tenant"},
		{"_secret", "_secret"},
		{"tenant_", "tenant_"},
		{"__double", "__double"},
		{"a_b_c_d", "a_b_c"},
		{"", ""},
	}
	for _, tt := range tests {
		got := tenant.ExtractTenantID(tt.key)
		if got != tt.want {
			t.Errorf("ExtractTenantID(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

// R14: Duplicate Content-Type headers — Go uses first value
func TestAttack_DuplicateContentTypeFirstValid(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h := New(up.URL, passEval2)
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(mustJSON(graphQLBody{Query: "{ hello }"})))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK && w.Code != http.StatusBadGateway {
		t.Errorf("expected 2xx for first Content-Type=json, got %d", w.Code)
	}
}

// R18: All blocked responses must be valid JSON
func TestAttack_BlockedResponseIsValidJSON(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not reach upstream") })
	defer up.Close()

	reasons := []string{
		"depth limit exceeded",
		`injected"quote`,
		"blocked\x00null",
		"reason with\nnewline",
		"evil\t\b\f\r",
	}
	for _, reason := range reasons {
		h := New(up.URL, &stubEvaluator2{result: &rules.Result{Allowed: false, Reason: reason}})
		req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(mustJSON(graphQLBody{Query: "{ hello }"})))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		body, _ := io.ReadAll(w.Result().Body)
		if !json.Valid(body) {
			t.Errorf("blocked response not valid JSON (reason=%q): %s", reason, string(body))
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 for blocked request, got %d", w.Code)
		}
	}
}
