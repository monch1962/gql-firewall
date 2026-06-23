// Package metrics provides Prometheus instrumentation for the GraphQL firewall.
package metrics

import (
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

// RecordRequest records a firewall decision.
func RecordRequest(outcome, operationType string, duration time.Duration) {
	RequestsTotal.WithLabelValues(outcome, operationType).Inc()
	RequestDuration.WithLabelValues(outcome).Observe(duration.Seconds())
}

// RecordBlock records a blocked request with the rule reason.
func RecordBlock(reason string) {
	RequestsBlocked.WithLabelValues(reason).Inc()
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
	OPAAuditBlocks.WithLabelValues(reason).Inc()
}

// Handler returns an HTTP handler for the /metrics endpoint.
func Handler() http.Handler {
	return promhttp.Handler()
}
