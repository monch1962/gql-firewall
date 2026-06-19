package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRecordRequest(t *testing.T) {
	RecordRequest("allowed", "query", time.Millisecond)
	// Counter should have incremented — verify via HTTP
	checkMetric(t, "gql_firewall_requests_total")
}

func TestRecordBlock(t *testing.T) {
	RecordBlock("depth limit exceeded")
	checkMetric(t, "gql_firewall_requests_blocked_total")
}

func TestRecordRuleEval(t *testing.T) {
	RecordRuleEval("depth_limit")
	checkMetric(t, "gql_firewall_rule_evaluations_total")
}

func TestRecordOPA(t *testing.T) {
	RecordOPA("allowed")
	checkMetric(t, "gql_firewall_opa_requests_total")
}

func TestMetricsEndpoint(t *testing.T) {
	// Record some data first
	RecordRequest("allowed", "query", 5*time.Millisecond)
	RecordRequest("blocked", "mutation", 2*time.Millisecond)
	RecordBlock("blocked field")
	RecordBlock("depth limit")

	// Hit the metrics endpoint
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body := w.Body.String()
	// Should contain our metric names
	checks := []string{
		"gql_firewall_requests_total",
		"gql_firewall_requests_blocked_total",
		"gql_firewall_request_duration_seconds",
		"gql_firewall_active_tenants",
		"gql_firewall_rule_evaluations_total",
	}
	for _, name := range checks {
		if !contains(body, name) {
			t.Errorf("expected metric %q in response", name)
		}
	}
}

func checkMetric(t *testing.T, name string) {
	t.Helper()
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, req)
	if !contains(w.Body.String(), name) {
		t.Errorf("expected metric %q in /metrics output", name)
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
