// gql-firewall — GraphQL firewall sidecar.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/monch1962/gql-firewall/internal/metrics"
	"github.com/monch1962/gql-firewall/internal/opa"
	"github.com/monch1962/gql-firewall/internal/parser"
	"github.com/monch1962/gql-firewall/internal/proxy"
	"github.com/monch1962/gql-firewall/internal/ratelimit"
)

const version = "0.4.0"

func main() {
	var (
		listenAddr      = flag.String("listen", ":8081", "Address to listen on")
		upstreamURL     = flag.String("upstream", "http://localhost:8080", "Upstream GraphQL server URL")
		opaEndpoint     = flag.String("opa", "", "OPA sidecar endpoint (e.g. http://localhost:8181/v1/data/graphql)")
		opaEmbed        = flag.String("opa-embed", "", "Path to Rego policy file for embedded evaluation (default: built-in policy)")
		opaParams       = flag.String("opa-params", "", "Path to parameters JSON file for embedded OPA")
		schemaPath      = flag.String("schema", "", "Path to GraphQL SDL schema file (optional)")
		adminListenAddr = flag.String("admin", ":8082", "Admin API listen address (set to empty to disable)")
		adminToken      = flag.String("admin-token", "", "Required bearer token for admin API (C-1 fix)")
		cacheTTL        = flag.Duration("opa-cache-ttl", 60*time.Second, "TTL for cached OPA decisions (0 = disabled)")
		opaFailClosed   = flag.Bool("opa-fail-closed", false, "Block requests when OPA is unreachable (C-2 fix)")
		opaAuditOnly    = flag.Bool("opa-audit-only", false, "Run OPA in audit-only mode (log would-be blocks, don't enforce)")
		maxBodyMB       = flag.Int64("max-body-mb", 1, "Maximum request body size in MB (H-6 fix)")
		tlsCert         = flag.String("tls-cert", "", "Path to TLS certificate file (H-5 fix)")
		tlsKey          = flag.String("tls-key", "", "Path to TLS private key file (H-5 fix)")
		metricsListen   = flag.String("metrics-listen", "", "Separate listen address for metrics (M-4 fix)")
		logFormat       = flag.String("log-format", "text", "Log format: text or json")
		ratePerSec      = flag.Float64("rate-limit", 0, "Per-tenant/IP rate limit (requests/sec, 0 = disabled)")
		rateBurst       = flag.Int("rate-burst", 0, "Rate limit burst size (0 = 2x rate-limit)")
	)
	flag.Parse()

	// Structured logging setup
	var logHandler slog.Handler
	switch *logFormat {
	case "json":
		logHandler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	default:
		logHandler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	slog.SetDefault(slog.New(logHandler))
	log.SetFlags(0)
	log.SetOutput(slog.NewLogLogger(logHandler, slog.LevelInfo).Writer())

	slog.Info("starting",
		"version", version,
		"listen", *listenAddr,
		"upstream", *upstreamURL,
		"log_format", *logFormat,
	)

	// Validate: at least one OPA mode must be configured
	if *opaEndpoint == "" && *opaEmbed == "" {
		log.Fatal("either --opa (sidecar) or --opa-embed (embedded Rego) must be configured")
	}
	if *opaEndpoint != "" && *opaEmbed != "" {
		log.Fatal("--opa and --opa-embed are mutually exclusive")
	}

	// Load SDL schema for schema-aware validation
	var schemaDoc *parser.SchemaInfo
	if *schemaPath != "" {
		var err error
		schemaDoc, err = parser.LoadSchema(*schemaPath)
		if err != nil {
			log.Fatalf("failed to load schema: %v", err)
		}
		log.Printf("loaded schema from %s (%d types)", *schemaPath, schemaDoc.TypeCount)
	}

	// Build the OPA evaluator
	opaStore := opa.NewDataStore()

	var opaEval opa.Evaluator
	if *opaEndpoint != "" {
		opaEval = opa.NewSidecar(*opaEndpoint)
		log.Printf("OPA sidecar configured at %s (cache TTL: %s, fail-closed: %v, audit-only: %v)",
			*opaEndpoint, *cacheTTL, *opaFailClosed, *opaAuditOnly)
	} else {
		// Embedded mode — policy file is required
		if *opaEmbed == "" {
			log.Fatal("--opa-embed requires a path to a Rego policy file")
		}
		policyData, err := os.ReadFile(*opaEmbed)
		if err != nil {
			log.Fatalf("failed to read policy file %s: %v", *opaEmbed, err)
		}

		// Load params if provided
		if *opaParams != "" {
			paramsData, err := os.ReadFile(*opaParams)
			if err != nil {
				log.Fatalf("failed to read params file %s: %v", *opaParams, err)
			}
			if err := opaStore.LoadParamsFromJSON(paramsData); err != nil {
				log.Fatalf("failed to parse params JSON: %v", err)
			}
			log.Printf("loaded OPA params from %s", *opaParams)
		}

		opaEval, err = opa.NewEmbedded(opa.EmbedConfig{
			Policy: string(policyData),
			Store:  opaStore,
		})
		if err != nil {
			log.Fatalf("failed to initialize embedded OPA: %v", err)
		}
		log.Printf("embedded OPA evaluator ready (audit-only: %v)", *opaAuditOnly)
	}

	evaluator := &compositeEvaluator{
		opa:          opaEval,
		opaStore:     opaStore,
		schema:       schemaDoc,
		cacheTTL:     *cacheTTL,
		opaFailClosed: *opaFailClosed,
		opaAuditOnly: *opaAuditOnly,
	}

	// Set up the admin API for live rule management
	if *adminListenAddr != "" {
		startAdminAPI(*adminListenAddr, *adminToken, evaluator, opaEval, opaStore)
	}

	// Create the proxy handler with body size limit (H-6 fix)
	handler, err := proxy.New(*upstreamURL, evaluator)
	if err != nil {
		slog.Error("invalid upstream URL", "error", err)
		os.Exit(1)
	}
	handler.MaxBodyBytes = *maxBodyMB * 1024 * 1024

	// Rate limiter (optional)
	var rateLimitHandler http.Handler = handler
	if *ratePerSec > 0 {
		burst := *rateBurst
		if burst <= 0 {
			burst = int(*ratePerSec) * 2
		}
		rl := ratelimit.New(ratelimit.Config{
			RequestsPerSecond: *ratePerSec,
			Burst:             burst,
		})
		defer rl.Stop()
		rateLimitHandler = rateLimitMiddleware(rl, handler)
		slog.Info("rate limiting enabled", "req_per_sec", *ratePerSec, "burst", burst)
	}

	// Build main mux — proxy
	mux := http.NewServeMux()
	mux.Handle("/", rateLimitHandler)

	// Metrics on separate port or main port (M-4 fix)
	if *metricsListen != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", metrics.Handler())
		metricsServer := &http.Server{
			Addr:              *metricsListen,
			Handler:           metricsMux,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       30 * time.Second,
		}
		go func() {
			log.Printf("metrics listening on %s", *metricsListen)
			if *tlsCert != "" && *tlsKey != "" {
				metricsServer.ListenAndServeTLS(*tlsCert, *tlsKey)
			} else {
				metricsServer.ListenAndServe()
			}
		}()
	} else {
		mux.Handle("/metrics", metrics.Handler())
	}

	// Server hardening: timeouts (H-7 fix)
	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	// Graceful shutdown (M-3 fix)
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down gracefully...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("shutdown error: %v", err)
		}
	}()

	log.Printf("listening on %s", *listenAddr)
	if *tlsCert != "" && *tlsKey != "" {
		log.Printf("TLS enabled (cert=%s)", *tlsCert)
		if err := server.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	} else {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}
}

// rateLimitMiddleware wraps an http.Handler with per-key token-bucket rate limiting.
func rateLimitMiddleware(rl *ratelimit.Limiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.RemoteAddr
		if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
			key = apiKey
		}
		if !rl.Allow(key) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limit exceeded","retry_after":1}`))
			slog.Warn("rate limit exceeded", "key", key, "path", r.URL.Path)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAdminAuth is HTTP middleware for admin API authentication (C-1 fix).
func requireAdminAuth(expectedToken string, next http.HandlerFunc) http.HandlerFunc {
	if expectedToken == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, `{"error": "authorization required"}`, http.StatusUnauthorized)
			return
		}
		var token string
		if len(auth) > 7 && auth[:7] == "Bearer " {
			token = auth[7:]
		} else {
			token = auth
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			http.Error(w, `{"error": "invalid authorization token"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// adminMux creates the admin API HTTP mux with all handlers configured.
func adminMux(token string, eval *compositeEvaluator, opaEval opa.Evaluator, store *opa.DataStore) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/admin/rules", requireAdminAuth(token, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		params := store.GetParams()
		if params == nil {
			params = map[string]interface{}{}
		}
		json.NewEncoder(w).Encode(params)
	}))

	mux.HandleFunc("/admin/rules/update", requireAdminAuth(token, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			http.Error(w, "use POST or PUT", http.StatusMethodNotAllowed)
			return
		}
		var params map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			http.Error(w, fmt.Sprintf(`{"error": "invalid JSON: %s"}`, err), http.StatusBadRequest)
			return
		}
		store.SetParams(params)
		if embedded, ok := opaEval.(*opa.EmbeddedEvaluator); ok {
			embedded.SetParams(params)
		}
		metrics.ConfigReloads.Inc()
		log.Printf("admin API: rules updated via OPA data store")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))

	mux.HandleFunc("/admin/tenants", requireAdminAuth(token, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(store.ListTenants())
	}))

	mux.HandleFunc("/admin/tenants/", requireAdminAuth(token, func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.URL.Path[len("/admin/tenants/"):]
		if tenantID == "" {
			http.Error(w, "tenant ID required", http.StatusBadRequest)
			return
		}

		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			cfg := store.GetTenant(tenantID)
			json.NewEncoder(w).Encode(cfg)

		case http.MethodPost, http.MethodPut:
			var cfg map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				http.Error(w, fmt.Sprintf("invalid JSON: %s", err), http.StatusBadRequest)
				return
			}
			store.SetTenant(tenantID, cfg)
			metrics.ActiveTenants.Set(float64(store.CountTenants()))
			log.Printf("admin API: tenant %q rules updated", tenantID)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

		case http.MethodDelete:
			store.DeleteTenant(tenantID)
			metrics.ActiveTenants.Set(float64(store.CountTenants()))
			log.Printf("admin API: tenant %q deleted", tenantID)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	mux.HandleFunc("/admin/stats", requireAdminAuth(token, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		stats := map[string]interface{}{
			"version": version,
			"uptime":  time.Since(startTime).String(),
			"tenants": store.CountTenants(),
		}
		json.NewEncoder(w).Encode(stats)
	}))

	mux.HandleFunc("/admin/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	return mux
}

// startAdminAPI starts the admin HTTP server for live rule management.
func startAdminAPI(addr, token string, eval *compositeEvaluator, opaEval opa.Evaluator, store *opa.DataStore) {
	mux := adminMux(token, eval, opaEval, store)
	adminServer := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		log.Printf("admin API listening on %s", addr)
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("admin API error: %v", err)
		}
	}()
}

var startTime = time.Now()

// compositeEvaluator runs schema validation then OPA evaluation with caching.
type compositeEvaluator struct {
	mu            sync.RWMutex
	opa           opa.Evaluator
	opaStore      *opa.DataStore
	schema        *parser.SchemaInfo
	cacheTTL      time.Duration
	cache         map[string]cachedDecision
	opaFailClosed bool
	opaAuditOnly  bool
}

type cachedDecision struct {
	result *opa.Result
	expiry time.Time
}

// Evaluate implements proxy.Evaluator for the OPA-only pipeline.
func (c *compositeEvaluator) Evaluate(info *parser.QueryInfo) (*opa.Result, error) {
	c.mu.RLock()
	schema := c.schema
	opaEval := c.opa
	cacheTTL := c.cacheTTL
	opaFailClosed := c.opaFailClosed
	opaAuditOnly := c.opaAuditOnly
	store := c.opaStore
	c.mu.RUnlock()

	// 1. Schema-aware validation
	if schema != nil {
		allowed, reason := schema.Validate(info)
		if !allowed {
			metrics.RecordBlock(reason)
			return &opa.Result{Allowed: false, Reason: reason}, nil
		}
	}

	// 2. Build OPA input with params and tenant config
	input := opa.BuildInput(info, store)

	// 3. OPA evaluation with caching
	cacheKey := decisionCacheKey(info)
	if cacheTTL > 0 {
		c.mu.RLock()
		if cached, ok := c.cache[cacheKey]; ok && time.Now().Before(cached.expiry) {
			c.mu.RUnlock()
			metrics.RecordOPA("cache_hit")
			if opaAuditOnly && !cached.result.Allowed {
				metrics.RecordOPAAuditBlock(cached.result.Reason)
				log.Printf("[AUDIT] OPA would block: %s (allowed in audit-only mode)", cached.result.Reason)
				return &opa.Result{Allowed: true}, nil
			}
			return cached.result, nil
		}
		c.mu.RUnlock()
	}

	result, err := opaEval.Evaluate(input)
	if err != nil {
		metrics.RecordOPA("error")
		if opaFailClosed {
			return &opa.Result{Allowed: false, Reason: "OPA unavailable — request blocked for safety"}, nil
		}
		return &opa.Result{Allowed: true}, nil
	}

	metrics.RecordOPA("evaluated")
	if !result.Allowed {
		if opaAuditOnly {
			metrics.RecordOPAAuditBlock(result.Reason)
			log.Printf("[AUDIT] OPA would block: %s (allowed in audit-only mode)", result.Reason)
			result = &opa.Result{Allowed: true}
		} else {
			metrics.RecordBlock(result.Reason)
		}
	}

	if cacheTTL > 0 {
		c.mu.Lock()
		if c.cache == nil {
			c.cache = make(map[string]cachedDecision)
		}
		c.cache[cacheKey] = cachedDecision{result: result, expiry: time.Now().Add(cacheTTL)}
		c.mu.Unlock()
	}

	return result, nil
}

// decisionCacheKey builds a cache key from query info.
func decisionCacheKey(info *parser.QueryInfo) string {
	pathHash := simpleHash(info.FieldPaths)
	return fmt.Sprintf("%s|%d|%d|%s", info.OperationType, info.Depth, info.FieldCount, pathHash)
}

// simpleHash produces a compact hash from a string slice for cache keys.
func simpleHash(parts []string) string {
	h := uint64(14695981039346656037)
	for _, s := range parts {
		for _, c := range []byte(s) {
			h ^= uint64(c)
			h *= 1099511628211
		}
	}
	return fmt.Sprintf("%08x", h)
}
