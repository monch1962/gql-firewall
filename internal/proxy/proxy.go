// Package proxy provides an HTTP reverse proxy that intercepts GraphQL
// requests, parses them, evaluates firewall rules via OPA, and either forwards
// or blocks the request.
package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/monch1962/gql-firewall/internal/metrics"
	"github.com/monch1962/gql-firewall/internal/opa"
	"github.com/monch1962/gql-firewall/internal/parser"
)

// DefaultMaxBodyBytes is the maximum request body size (1MB).
const DefaultMaxBodyBytes = 1 * 1024 * 1024

// DefaultParseTimeout is the maximum time allowed for GraphQL query parsing.
const DefaultParseTimeout = 5 * time.Second

// sanitizeError returns a generic error message suitable for client responses.
func sanitizeError(context string) string {
	switch context {
	case "body":
		return "invalid request body"
	case "json":
		return "invalid JSON in request"
	case "query":
		return "invalid GraphQL query"
	case "eval":
		return "rule evaluation error"
	default:
		return "request processing error"
	}
}

// sanitizeReason strips characters from a reason string that could break
// JSON parsers or inject content into HTTP responses.
func sanitizeReason(reason string) string {
	var b strings.Builder
	b.Grow(len(reason))
	for _, r := range reason {
		if r >= 32 && r <= 126 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Evaluator is the interface for rule evaluation.
type Evaluator interface {
	Evaluate(info *parser.QueryInfo) (*opa.Result, error)
}

// graphQLBody represents the expected JSON body of a GraphQL HTTP request.
type graphQLBody struct {
	Query         string          `json:"query"`
	OperationName string          `json:"operationName,omitempty"`
	Variables     json.RawMessage `json:"variables,omitempty"`
	Extensions    json.RawMessage `json:"extensions,omitempty"`
}

// batchGraphQLBody is used for batch requests sent as JSON arrays.
type batchGraphQLBody []graphQLBody

// Handler is an HTTP handler that proxies GraphQL requests through a firewall.
type Handler struct {
	upstream             *httputil.ReverseProxy
	evaluator            Evaluator
	MaxBodyBytes         int64
	MaxCacheSize         int
	ParseTimeout         time.Duration
	disablePanicRecovery bool // for testing
}

// New creates a new proxy handler that forwards to upstreamURL after
// evaluating requests through the provided evaluator.
func New(upstreamURL string, evaluator Evaluator) (*Handler, error) {
	u, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL %q: %w", upstreamURL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid upstream URL %q: must include scheme and host", upstreamURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("invalid upstream URL scheme %q: must be http or https", u.Scheme)
	}
	return &Handler{
		upstream:     newHostFixedReverseProxy(u),
		evaluator:    evaluator,
		MaxBodyBytes: DefaultMaxBodyBytes,
		ParseTimeout: DefaultParseTimeout,
	}, nil
}

// newHostFixedReverseProxy creates a ReverseProxy that overrides the Host
// header to match the upstream target, preventing Host header injection
// (CAPEC-664: SSRF via Host manipulation).
func newHostFixedReverseProxy(target *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	origDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		origDirector(r)
		r.Host = r.URL.Host
	}
	return proxy
}

// MustNew is like New but panics on error. Used in tests and bootstrap code.
func MustNew(upstreamURL string, evaluator Evaluator) *Handler {
	h, err := New(upstreamURL, evaluator)
	if err != nil {
		panic(err)
	}
	return h
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Prevent panic from crashing the process (H1 fix)
	if !h.disablePanicRecovery {
		defer h.recoverPanic(w, r)
	}

	if isGraphQLPath(r.URL.Path) {
		switch r.Method {
		case http.MethodPost:
			if !hasJSONContentType(r.Header) {
				http.Error(w, `{"error": "Content-Type must be application/json"}`, http.StatusUnsupportedMediaType)
				return
			}
			h.handleGraphQL(w, r)
			return
		case http.MethodGet:
			h.handleGraphQLGet(w, r)
			return
		default:
			// Reject all other HTTP methods on GraphQL paths to prevent
			// verb tampering bypass (CAPEC-274).
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, `{"error": "method not allowed on GraphQL endpoint"}`, http.StatusMethodNotAllowed)
			return
		}
	}
	h.upstream.ServeHTTP(w, r)
}

// recoverPanic catches panics from downstream handlers and returns a 500
// instead of crashing the process.
func (h *Handler) recoverPanic(w http.ResponseWriter, r *http.Request) {
	if rec := recover(); rec != nil {
		log.Printf("[PANIC] recovered in %s %s: %v", r.Method, r.URL.Path, rec)
		metrics.RecordRequest("error", "unknown", 0)
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
	}
}

func isGraphQLPath(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, "/graphql")
}

func hasJSONContentType(headers http.Header) bool {
	ct := headers.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		return false
	}
	// Allow application/json, application/json; charset=utf-8, etc.
	// Reject application/json-fake or application/jsonml
	if len(ct) > len("application/json") {
		next := ct[len("application/json")]
		return next == ';' || next == ' '
	}
	return true
}

func (h *Handler) handleGraphQL(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Apply body size limit only when positive (0 or negative = unlimited)
	if h.MaxBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, h.MaxBodyBytes)
	}

	bodyBytes, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		if err.Error() == "http: request body too large" {
			http.Error(w, fmt.Sprintf(`{"error": %q}`, sanitizeError("body")), http.StatusRequestEntityTooLarge)
			metrics.RecordRequest("error", "unknown", time.Since(start))
			return
		}
		http.Error(w, fmt.Sprintf(`{"error": %q}`, sanitizeError("body")), http.StatusBadRequest)
		metrics.RecordRequest("error", "unknown", time.Since(start))
		return
	}

	// Detect batch request: body starts with '['
	trimmed := bytes.TrimLeft(bodyBytes, " 	\r\n")
	isBatch := len(trimmed) > 0 && trimmed[0] == '['

	if isBatch {
		h.handleGraphQLBatch(w, r, bodyBytes, start)
		return
	}

	// Single request — use json.Decoder to reject trailing garbage
	var gqlReq graphQLBody
	dec := json.NewDecoder(bytes.NewReader(bodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&gqlReq); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": %q}`, sanitizeError("json")), http.StatusBadRequest)
		metrics.RecordRequest("error", "unknown", time.Since(start))
		return
	}
	// Reject trailing data after the JSON object (injection via garbage suffix)
	if dec.More() {
		http.Error(w, fmt.Sprintf(`{"error": %q}`, sanitizeError("json")), http.StatusBadRequest)
		metrics.RecordRequest("error", "unknown", time.Since(start))
		return
	}

	if gqlReq.Query == "" {
		http.Error(w, fmt.Sprintf(`{"error": %q}`, sanitizeError("query")), http.StatusBadRequest)
		metrics.RecordRequest("error", "unknown", time.Since(start))
		return
	}

	// Parse GraphQL query with timeout to prevent CPU exhaustion (H3 fix)
	queryInfo, err := parseQueryWithTimeout(gqlReq.Query, h.ParseTimeout)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": %q}`, sanitizeError("query")), http.StatusBadRequest)
		metrics.RecordRequest("error", "unknown", time.Since(start))
		return
	}

	// Enrich with variables from request
	if len(gqlReq.Variables) > 0 {
		queryInfo.RequestVariables = gqlReq.Variables
	}

	h.evaluateAndForward(w, r, bodyBytes, queryInfo, start)
}

// handleGraphQLGet handles GET requests to GraphQL endpoints.
// The query is read from the URL query parameter, variables from JSON in the
// variables query parameter. This follows the GraphQL-over-HTTP specification.
func (h *Handler) handleGraphQLGet(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	query := r.URL.Query().Get("query")
	if query == "" {
		http.Error(w, fmt.Sprintf(`{"error": %q}`, sanitizeError("query")), http.StatusBadRequest)
		metrics.RecordRequest("error", "unknown", time.Since(start))
		return
	}

	queryInfo, err := parseQueryWithTimeout(query, h.ParseTimeout)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": %q}`, sanitizeError("query")), http.StatusBadRequest)
		metrics.RecordRequest("error", "unknown", time.Since(start))
		return
	}

	// Parse variables from query parameter (JSON object)
	if varsParam := r.URL.Query().Get("variables"); varsParam != "" {
		queryInfo.RequestVariables = json.RawMessage(varsParam)
	}

	// Build the request body for forwarding to upstream
	forwardBody, _ := json.Marshal(graphQLBody{
		Query:         query,
		OperationName: r.URL.Query().Get("operationName"),
		Variables:     queryInfo.RequestVariables,
	})

	h.evaluateAndForward(w, r, forwardBody, queryInfo, start)
}

// handleGraphQLBatch handles batch GraphQL requests (JSON array of query objects).
// Each query is parsed and evaluated independently. If ANY query is blocked by
// OPA, the entire batch is rejected.
func (h *Handler) handleGraphQLBatch(w http.ResponseWriter, r *http.Request, bodyBytes []byte, start time.Time) {
	var batch batchGraphQLBody
	if err := json.Unmarshal(bodyBytes, &batch); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": %q}`, sanitizeError("json")), http.StatusBadRequest)
		metrics.RecordRequest("error", "unknown", time.Since(start))
		return
	}

	if len(batch) == 0 {
		http.Error(w, fmt.Sprintf(`{"error": %q}`, sanitizeError("query")), http.StatusBadRequest)
		metrics.RecordRequest("error", "unknown", time.Since(start))
		return
	}

	// Evaluate each query in the batch
	firstOpType := "unknown"
	for i, req := range batch {
		if req.Query == "" {
			http.Error(w, fmt.Sprintf(`{"error": "batch item %d has empty query"}`, i), http.StatusBadRequest)
			metrics.RecordRequest("error", "unknown", time.Since(start))
			return
		}
		queryInfo, err := parseQueryWithTimeout(req.Query, h.ParseTimeout)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error": "invalid GraphQL query at batch index %d"}`, i), http.StatusBadRequest)
			metrics.RecordRequest("error", "unknown", time.Since(start))
			return
		}
		if len(req.Variables) > 0 {
			queryInfo.RequestVariables = req.Variables
		}
		if i == 0 {
			firstOpType = queryInfo.OperationType
		}

		result, err := h.evaluator.Evaluate(queryInfo)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error": %q}`, sanitizeError("eval")), http.StatusInternalServerError)
			metrics.RecordRequest("error", queryInfo.OperationType, time.Since(start))
			return
		}
		if !result.Allowed {
			w.Header().Set("Content-Type", "application/json")
			setSecurityHeaders(w)
			w.WriteHeader(http.StatusForbidden)
			reason := sanitizeReason(result.Reason)
			fmt.Fprintf(w, `{"error": "request blocked", "reason": %q}`, reason)
			metrics.RecordBlock(result.Reason)
			metrics.RecordRequest("blocked", queryInfo.OperationType, time.Since(start))
			return
		}
	}

	metrics.RecordRequest("allowed", firstOpType, time.Since(start))

	// All queries passed — forward the original batch body
	setSecurityHeaders(w)
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))
	h.upstream.ServeHTTP(w, r)
}

// evaluateAndForward evaluates a single query and forwards it upstream if allowed.
func (h *Handler) evaluateAndForward(w http.ResponseWriter, r *http.Request, bodyBytes []byte, queryInfo *parser.QueryInfo, start time.Time) {
	// Extract tenant from X-API-Key header
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		queryInfo.TenantID = extractTenantID(apiKey)
	}

	metrics.RecordRuleEval(fmt.Sprintf("op_%s", queryInfo.OperationType))

	result, err := h.evaluator.Evaluate(queryInfo)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": %q}`, sanitizeError("eval")), http.StatusInternalServerError)
		metrics.RecordRequest("error", queryInfo.OperationType, time.Since(start))
		return
	}

	if !result.Allowed {
		w.Header().Set("Content-Type", "application/json")
		setSecurityHeaders(w)
		w.WriteHeader(http.StatusForbidden)
		reason := sanitizeReason(result.Reason)
		fmt.Fprintf(w, `{"error": "request blocked", "reason": %q}`, reason)
		metrics.RecordBlock(result.Reason)
		metrics.RecordRequest("blocked", queryInfo.OperationType, time.Since(start))
		return
	}

	metrics.RecordRequest("allowed", queryInfo.OperationType, time.Since(start))

	// Set security headers on forwarded responses too
	setSecurityHeaders(w)

	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))
	h.upstream.ServeHTTP(w, r)
}

// parseQueryWithTimeout runs GraphQL parsing with a timeout to prevent
// CPU exhaustion from crafted queries (H3 fix).
func parseQueryWithTimeout(query string, timeout time.Duration) (*parser.QueryInfo, error) {
	type result struct {
		info *parser.QueryInfo
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		info, err := parser.Parse(query)
		ch <- result{info, err}
	}()
	select {
	case r := <-ch:
		return r.info, r.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("query parsing timed out")
	}
}

// setSecurityHeaders adds hardening headers to responses (H2 fix).
func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}

// extractTenantID extracts a tenant identifier from an API key header.
func extractTenantID(apiKey string) string {
	if apiKey == "" {
		return ""
	}
	for i := len(apiKey) - 1; i >= 0; i-- {
		if apiKey[i] == '_' && hasLeadingContent(apiKey[:i]) && i < len(apiKey)-1 {
			return apiKey[:i]
		}
	}
	return apiKey
}

func hasLeadingContent(s string) bool {
	for i := range len(s) {
		if s[i] != '_' && s[i] != ' ' {
			return true
		}
	}
	return false
}
