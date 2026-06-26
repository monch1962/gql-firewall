package metrics

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestActiveTenantsGauge(t *testing.T) {
	ActiveTenants.Set(5)
	checkMetric(t, `gql_firewall_active_tenants 5`)
}

func TestConfigReloadsCounter(t *testing.T) {
	before := countMetric(t, "gql_firewall_config_reloads_total")
	ConfigReloads.Inc()
	after := countMetric(t, "gql_firewall_config_reloads_total")
	if after <= before {
		t.Errorf("expected config_reloads_total to increase: before=%d after=%d", before, after)
	}
	// Reset for other tests
}

func TestRequestDurationHistogram(t *testing.T) {
	RecordRequest("allowed", "query", 50*time.Millisecond)
	RecordRequest("blocked", "mutation", 100*time.Millisecond)
	checkMetric(t, `gql_firewall_request_duration_seconds_bucket`)
}

func TestRequestsBlockedByReason(t *testing.T) {
	RecordBlock("test-reason-one")
	RecordBlock("test-reason-two")
	body := scrapeMetrics(t)
	if !strings.Contains(body, `reason="test-reason-one"`) {
		t.Errorf("expected reason label in blocked metric, got body: %s", body)
	}
}

func TestMetricsEndpoint_ContainsAllMetrics(t *testing.T) {
	// Record some data first
	RecordRequest("allowed", "query", time.Millisecond)
	RecordBlock("depth_test")
	RecordRuleEval("depth_limit")
	RecordOPA("ok")
	RecordOPAAuditBlock("would block introspection")
	ConfigReloads.Inc()
	ActiveTenants.Set(3)

	body := scrapeMetrics(t)

	checks := []string{
		"gql_firewall_requests_total",
		"gql_firewall_requests_blocked_total",
		"gql_firewall_request_duration_seconds",
		"gql_firewall_active_tenants",
		"gql_firewall_rule_evaluations_total",
		"gql_firewall_config_reloads_total",
		"gql_firewall_opa_requests_total",
		"gql_firewall_opa_audit_blocks_total",
	}
	for _, name := range checks {
		if !strings.Contains(body, name) {
			t.Errorf("expected metric %q in /metrics output", name)
		}
	}
}

// countMetric returns the integer value of a counter metric from /metrics.
func countMetric(t *testing.T, name string) int {
	t.Helper()
	body := scrapeMetrics(t)
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, name) && !strings.Contains(line, "#") {
			parts := strings.Split(line, " ")
			if len(parts) >= 2 {
				var val int
				if _, err := fmt.Sscanf(parts[len(parts)-1], "%d", &val); err == nil {
					return val
				}
			}
		}
	}
	return -1
}

// scrapeMetrics fetches the /metrics endpoint and returns the body.
func scrapeMetrics(t *testing.T) string {
	t.Helper()
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /metrics, got %d", resp.StatusCode)
	}
	return w.Body.String()
}
