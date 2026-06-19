// Package proxy provides an HTTP reverse proxy that intercepts GraphQL
// requests, parses them, evaluates firewall rules, and either forwards
// or blocks the request.
package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/monch1962/gql-firewall/internal/metrics"
	"github.com/monch1962/gql-firewall/internal/parser"
	"github.com/monch1962/gql-firewall/internal/rules"
)

// Evaluator is the interface for rule evaluation.
type Evaluator interface {
	Evaluate(info *parser.QueryInfo) (*rules.Result, error)
}

// graphQLBody represents the expected JSON body of a GraphQL HTTP request.
type graphQLBody struct {
	Query         string          `json:"query"`
	OperationName string          `json:"operationName,omitempty"`
	Variables     json.RawMessage `json:"variables,omitempty"`
}

// Handler is an HTTP handler that proxies GraphQL requests through a firewall.
type Handler struct {
	upstream    *httputil.ReverseProxy
	upstreamURL *url.URL
	evaluator   Evaluator
}

// New creates a new proxy handler that forwards to upstreamURL after
// evaluating requests through the provided evaluator.
func New(upstreamURL string, evaluator Evaluator) *Handler {
	u, _ := url.Parse(upstreamURL)
	return &Handler{
		upstream:    httputil.NewSingleHostReverseProxy(u),
		upstreamURL: u,
		evaluator:   evaluator,
	}
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only inspect POST requests to /graphql
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/graphql") {
		h.handleGraphQL(w, r)
		return
	}

	// Pass through all other requests
	h.upstream.ServeHTTP(w, r)
}

func (h *Handler) handleGraphQL(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Read and preserve the body for upstream forwarding
	bodyBytes, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "cannot read request body: %s"}`, err), http.StatusBadRequest)
		metrics.RecordRequest("error", "unknown", time.Since(start))
		return
	}

	// Parse the GraphQL JSON body
	var gqlReq graphQLBody
	if err := json.Unmarshal(bodyBytes, &gqlReq); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "invalid JSON body: %s"}`, err), http.StatusBadRequest)
		metrics.RecordRequest("error", "unknown", time.Since(start))
		return
	}

	if gqlReq.Query == "" {
		http.Error(w, `{"error": "missing 'query' field in request body"}`, http.StatusBadRequest)
		metrics.RecordRequest("error", "unknown", time.Since(start))
		return
	}

	// Parse the GraphQL query
	queryInfo, err := parser.Parse(gqlReq.Query)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "invalid GraphQL query: %s"}`, err), http.StatusBadRequest)
		metrics.RecordRequest("error", "unknown", time.Since(start))
		return
	}

	metrics.RecordRuleEval(fmt.Sprintf("op_%s", queryInfo.OperationType))

	// Evaluate rules
	result, err := h.evaluator.Evaluate(queryInfo)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "rule evaluation error: %s"}`, err), http.StatusInternalServerError)
		metrics.RecordRequest("error", queryInfo.OperationType, time.Since(start))
		return
	}

	if !result.Allowed {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"error": "request blocked", "reason": %q}`, result.Reason)
		metrics.RecordBlock(result.Reason)
		metrics.RecordRequest("blocked", queryInfo.OperationType, time.Since(start))
		return
	}

	// Forward to upstream — restore the body
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))

	// Use a response modifier to capture the upstream response status
	modifier := func(resp *http.Response) error {
		metrics.RecordRequest("allowed", queryInfo.OperationType, time.Since(start))
		return nil
	}

	proxy := httputil.NewSingleHostReverseProxy(h.upstreamURL)
	proxy.ModifyResponse = modifier
	proxy.ServeHTTP(w, r)
}
