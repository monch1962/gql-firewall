// Package proxy provides an HTTP reverse proxy that intercepts GraphQL
// requests, parses them, evaluates firewall rules via OPA, and either forwards
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
	"github.com/monch1962/gql-firewall/internal/opa"
	"github.com/monch1962/gql-firewall/internal/parser"
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
}

// Handler is an HTTP handler that proxies GraphQL requests through a firewall.
type Handler struct {
	upstream     *httputil.ReverseProxy
	evaluator    Evaluator
	MaxBodyBytes int64
	MaxCacheSize int
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
	return &Handler{
		upstream:     httputil.NewSingleHostReverseProxy(u),
		evaluator:    evaluator,
		MaxBodyBytes: DefaultMaxBodyBytes,
	}, nil
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
	if r.Method == http.MethodPost && isGraphQLPath(r.URL.Path) {
		if !hasJSONContentType(r.Header) {
			http.Error(w, `{"error": "Content-Type must be application/json"}`, http.StatusUnsupportedMediaType)
			return
		}
		h.handleGraphQL(w, r)
		return
	}
	h.upstream.ServeHTTP(w, r)
}

func isGraphQLPath(path string) bool {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, "/graphql") {
		return true
	}
	return false
}

func hasJSONContentType(headers http.Header) bool {
	ct := headers.Get("Content-Type")
	return strings.HasPrefix(ct, "application/json")
}

func (h *Handler) handleGraphQL(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	r.Body = http.MaxBytesReader(w, r.Body, h.MaxBodyBytes)

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

	queryInfo, err := parser.Parse(gqlReq.Query)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": %q}`, sanitizeError("query")), http.StatusBadRequest)
		metrics.RecordRequest("error", "unknown", time.Since(start))
		return
	}

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
		w.WriteHeader(http.StatusForbidden)
		reason := sanitizeReason(result.Reason)
		fmt.Fprintf(w, `{"error": "request blocked", "reason": %q}`, reason)
		metrics.RecordBlock(result.Reason)
		metrics.RecordRequest("blocked", queryInfo.OperationType, time.Since(start))
		return
	}

	metrics.RecordRequest("allowed", queryInfo.OperationType, time.Since(start))

	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))
	h.upstream.ServeHTTP(w, r)
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
