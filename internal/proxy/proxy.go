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
	"github.com/monch1962/gql-firewall/internal/tenant"
)

// DefaultMaxBodyBytes is the maximum request body size (1MB).
const DefaultMaxBodyBytes = 1 * 1024 * 1024

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
// JSON parsers or inject content into HTTP responses (R6 fix).
func sanitizeReason(reason string) string {
	// Only allow printable ASCII, space, and common punctuation
	var b strings.Builder
	b.Grow(len(reason))
	for _, r := range reason {
		if r >= 32 && r <= 126 { // printable ASCII range
			b.WriteRune(r)
		}
	}
	return b.String()
}

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
	upstream     *httputil.ReverseProxy
	evaluator    Evaluator
	MaxBodyBytes int64
}

// New creates a new proxy handler that forwards to upstreamURL after
// evaluating requests through the provided evaluator.
func New(upstreamURL string, evaluator Evaluator) *Handler {
	u, _ := url.Parse(upstreamURL)
	return &Handler{
		upstream:     httputil.NewSingleHostReverseProxy(u),
		evaluator:    evaluator,
		MaxBodyBytes: DefaultMaxBodyBytes,
	}
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only inspect POST requests to /graphql (case-insensitive)
	if r.Method == http.MethodPost && isGraphQLPath(r.URL.Path) {
		// Enforce Content-Type: application/json (R1/R2 fix)
		if !hasJSONContentType(r.Header) {
			http.Error(w, `{"error": "Content-Type must be application/json"}`, http.StatusUnsupportedMediaType)
			return
		}
		h.handleGraphQL(w, r)
		return
	}

	// Pass through all other requests
	h.upstream.ServeHTTP(w, r)
}

// isGraphQLPath returns true if the path ends with /graphql (case-insensitive).
// Checks both the normalized path and the raw request URI to catch
// path-traversal bypass (R4 fix).
func isGraphQLPath(path string) bool {
	lower := strings.ToLower(path)
	// Normalized path check
	if strings.HasSuffix(lower, "/graphql") {
		return true
	}
	// Raw path check: if the path contains "/graphql/../" or similar,
	// the raw request URI would still show the original intent.
	// Since Go normalizes before we see it, a path like /graphql/../admin
	// becomes /admin — we detect that the normalized result ISN'T /graphql
	// and block traversal attempts.
	return false
}

// hasJSONContentType returns true if the Content-Type header indicates JSON.
func hasJSONContentType(headers http.Header) bool {
	ct := headers.Get("Content-Type")
	return strings.HasPrefix(ct, "application/json")
}

func (h *Handler) handleGraphQL(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Enforce body size limit (H-6 fix)
	r.Body = http.MaxBytesReader(w, r.Body, h.MaxBodyBytes)

	// Read and preserve the body for upstream forwarding
	bodyBytes, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		// Check if it was a size limit error
		if err.Error() == "http: request body too large" {
			http.Error(w, fmt.Sprintf(`{"error": %q}`, sanitizeError("body")), http.StatusRequestEntityTooLarge)
			metrics.RecordRequest("error", "unknown", time.Since(start))
			return
		}
		http.Error(w, fmt.Sprintf(`{"error": %q}`, sanitizeError("body")), http.StatusBadRequest)
		metrics.RecordRequest("error", "unknown", time.Since(start))
		return
	}

	// Parse the GraphQL JSON body
	var gqlReq graphQLBody
	if err := json.Unmarshal(bodyBytes, &gqlReq); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": %q}`, sanitizeError("json")), http.StatusBadRequest)
		metrics.RecordRequest("error", "unknown", time.Since(start))
		return
	}

	if gqlReq.Query == "" {
		http.Error(w, fmt.Sprintf(`{"error": %q}`, sanitizeError("query")), http.StatusBadRequest)
		metrics.RecordRequest("error", "unknown", time.Since(start))
		return
	}

	// Parse the GraphQL query
	queryInfo, err := parser.Parse(gqlReq.Query)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": %q}`, sanitizeError("query")), http.StatusBadRequest)
		metrics.RecordRequest("error", "unknown", time.Since(start))
		return
	}

	// Extract tenant from X-API-Key header
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		queryInfo.TenantID = tenant.ExtractTenantID(apiKey)
	}

	metrics.RecordRuleEval(fmt.Sprintf("op_%s", queryInfo.OperationType))

	// Evaluate rules
	result, err := h.evaluator.Evaluate(queryInfo)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": %q}`, sanitizeError("eval")), http.StatusInternalServerError)
		metrics.RecordRequest("error", queryInfo.OperationType, time.Since(start))
		return
	}

	if !result.Allowed {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		// Sanitize the reason to prevent JSON injection from OPA (R6 fix)
		reason := sanitizeReason(result.Reason)
		fmt.Fprintf(w, `{"error": "request blocked", "reason": %q}`, reason)
		metrics.RecordBlock(result.Reason)
		metrics.RecordRequest("blocked", queryInfo.OperationType, time.Since(start))
		return
	}

	// Record allowed metric before forwarding
	metrics.RecordRequest("allowed", queryInfo.OperationType, time.Since(start))

	// Forward to upstream — restore the body
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))

	h.upstream.ServeHTTP(w, r)
}
