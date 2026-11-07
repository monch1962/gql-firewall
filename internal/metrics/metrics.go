// Package metrics provides Prometheus instrumentation for the GraphQL firewall.
package metrics

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

var (
	// RequestsTotal counts all GraphQL requests by outcome.
	RequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gql_firewall_requests_total",
		Help: "Total number of GraphQL requests processed",
	}, []string{"outcome", "operation_type"})

	// RequestsBlocked counts blocked requests by rule reason.
	RequestsBlocked = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gql_firewall_requests_blocked_total",
		Help: "Total number of GraphQL requests blocked, by rule reason",
	}, []string{"reason"})

	// RequestDuration tracks latency of the full firewall pipeline.
	RequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "gql_firewall_request_duration_seconds",
		Help:    "Latency of firewall pipeline processing",
		Buckets: prometheus.DefBuckets,
	}, []string{"outcome"})

	// ActiveTenants tracks the number of tenants with active policies.
	ActiveTenants = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gql_firewall_active_tenants",
		Help: "Number of tenants currently configured",
	})

	// RuleEvaluations counts rule evaluation events by rule type.
	RuleEvaluations = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gql_firewall_rule_evaluations_total",
		Help: "Total number of rule evaluations, by rule type",
	}, []string{"rule"})

	// ConfigReloads counts config hot-reload events.
	ConfigReloads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gql_firewall_config_reloads_total",
		Help: "Total number of config hot-reloads",
	})

	// OPARequests counts OPA sidecar calls by outcome.
	OPARequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gql_firewall_opa_requests_total",
		Help: "Total number of OPA sidecar requests, by outcome",
	}, []string{"outcome"})

	// OPAAuditBlocks counts requests that OPA would have blocked in audit-only mode.
	OPAAuditBlocks = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gql_firewall_opa_audit_blocks_total",
		Help: "Total number of requests OPA would have blocked (audit-only mode), by reason",
	}, []string{"reason"})
)

// ReasonLabel maps a rule reason to a bounded label value. Rule reasons can
// embed attacker-supplied text (field names, operation names), so they must
// never be used as label values verbatim: each unique string creates a
// permanent new Prometheus time series (cardinality bomb → memory DoS).
// The full reason is still logged and returned to the client.
func ReasonLabel(reason string) string {
	switch {
	case reason == "":
		return "unspecified"
	case strings.Contains(reason, "malformed request"):
		return "malformed_request"
	case strings.Contains(reason, "does not exist on type"):
		return "schema_unknown_field"
	case strings.Contains(reason, "cannot resolve return type"):
		return "schema_unresolved_type"
	case strings.Contains(reason, "not found in schema"):
		return "schema_unknown_type"
	case strings.Contains(reason, "introspection"):
		return "introspection"
	case strings.Contains(reason, "persisted query"):
		return "persisted_query"
	case strings.Contains(reason, "OPA unavailable"):
		return "opa_unavailable"
	case strings.Contains(reason, "tenant"):
		return "tenant_policy"
	case strings.Contains(reason, "depth"):
		return "depth_limit"
	case strings.Contains(reason, "field count"), strings.Contains(reason, "alias bomb"):
		return "field_count_limit"
	case strings.Contains(reason, "directive"):
		return "directive_limit"
	case strings.Contains(reason, "batch size"):
		return "batch_size_limit"
	case strings.Contains(reason, "fragment spread"):
		return "fragment_spread_limit"
	case strings.Contains(reason, "argument depth"):
		return "argument_depth_limit"
	case strings.Contains(reason, "list fields"):
		return "list_count_limit"
	case strings.Contains(reason, "cost"):
		return "cost_budget"
	case strings.Contains(reason, "operation name"):
		return "operation_name"
	case strings.Contains(reason, "operation type"):
		return "operation_type"
	case strings.Contains(reason, "allowlist"):
		return "not_allowlisted"
	case strings.Contains(reason, "is blocked"), strings.Contains(reason, "blocked"):
		return "field_blocked"
	default:
		return "other"
	}
}

// RecordRequest records a firewall decision.
func RecordRequest(outcome, operationType string, duration time.Duration) {
	RequestsTotal.WithLabelValues(outcome, operationType).Inc()
	RequestDuration.WithLabelValues(outcome).Observe(duration.Seconds())
}

// RecordBlock records a blocked request with the rule reason.
func RecordBlock(reason string) {
	RequestsBlocked.WithLabelValues(ReasonLabel(reason)).Inc()
}

// RecordRuleEval increments a rule evaluation counter.
func RecordRuleEval(rule string) {
	RuleEvaluations.WithLabelValues(rule).Inc()
}

// RecordOPA records an OPA sidecar call result.
func RecordOPA(outcome string) {
	OPARequests.WithLabelValues(outcome).Inc()
}

// RecordOPAAuditBlock records a request that OPA would have blocked in audit-only mode.
func RecordOPAAuditBlock(reason string) {
	OPAAuditBlocks.WithLabelValues(ReasonLabel(reason)).Inc()
}

// Handler returns an HTTP handler for the /metrics endpoint.
func Handler() http.Handler {
	return promhttp.Handler()
}
