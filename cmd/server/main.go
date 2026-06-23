// gql-firewall — GraphQL firewall sidecar.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/monch1962/gql-firewall/internal/config"
	"github.com/monch1962/gql-firewall/internal/metrics"
	"github.com/monch1962/gql-firewall/internal/opa"
	"github.com/monch1962/gql-firewall/internal/parser"
	"github.com/monch1962/gql-firewall/internal/proxy"
	"github.com/monch1962/gql-firewall/internal/rules"
	"github.com/monch1962/gql-firewall/internal/tenant"
)

const version = "0.3.0"

func main() {
	var (
		listenAddr      = flag.String("listen", ":8081", "Address to listen on")
		upstreamURL     = flag.String("upstream", "http://localhost:8080", "Upstream GraphQL server URL")
		configPath      = flag.String("config", "config/rules.json", "Path to rules configuration JSON file")
		opaEndpoint     = flag.String("opa", "", "OPA sidecar endpoint (optional)")
		schemaPath      = flag.String("schema", "", "Path to GraphQL SDL schema file (optional)")
		adminListenAddr = flag.String("admin", ":8082", "Admin API listen address (set to empty to disable)")
		adminToken      = flag.String("admin-token", "", "Required bearer token for admin API (C-1 fix)")
		cacheTTL        = flag.Duration("opa-cache-ttl", 60*time.Second, "TTL for cached OPA decisions (0 = disabled)")
		opaFailClosed   = flag.Bool("opa-fail-closed", false, "Block requests when OPA is unreachable (C-2 fix)")
		maxBodyMB       = flag.Int64("max-body-mb", 1, "Maximum request body size in MB (H-6 fix)")
		tlsCert         = flag.String("tls-cert", "", "Path to TLS certificate file (H-5 fix)")
		tlsKey          = flag.String("tls-key", "", "Path to TLS private key file (H-5 fix)")
		metricsListen   = flag.String("metrics-listen", "", "Separate listen address for metrics (M-4 fix; empty = serve on main port)")
		opaAuditOnly    = flag.Bool("opa-audit-only", false, "Run OPA in audit-only mode: log would-be blocks without enforcing")
	)
	flag.Parse()

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Printf("gql-firewall v%s starting (listen=%s upstream=%s)", version, *listenAddr, *upstreamURL)

	// Load local rules configuration
	rulesCfg := &rules.Config{}
	if *configPath != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			log.Fatalf("failed to load config: %v", err)
		}
		if err := rules.Validate(cfg); err != nil {
			log.Fatalf("invalid config: %v", err)
		}
		rulesCfg = cfg
		log.Printf("loaded config from %s", *configPath)
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

	// Set up OPA client (optional)
	opaClient := opa.New(*opaEndpoint)
	if *opaEndpoint != "" {
		if *opaAuditOnly {
			log.Printf("OPA sidecar configured at %s (AUDIT-ONLY — blocks are logged, not enforced; cache TTL: %s, fail-closed: %v)", *opaEndpoint, *cacheTTL, *opaFailClosed)
		} else {
			log.Printf("OPA sidecar configured at %s (cache TTL: %s, fail-closed: %v)", *opaEndpoint, *cacheTTL, *opaFailClosed)
		}
	} else {
		log.Printf("no OPA endpoint configured — using local rules only")
	}

	// Build the composite evaluator: local rules → tenant config → caching OPA → schema
	tenantStore := tenant.New(rulesCfg)

	evaluator := &compositeEvaluator{
		local:         rulesCfg,
		tenants:       tenantStore,
		opa:           opaClient,
		schema:        schemaDoc,
		cacheTTL:      *cacheTTL,
		opaFailClosed: *opaFailClosed,
		opaAuditOnly:  *opaAuditOnly,
	}

	// Set up the admin API for live rule management
	if *adminListenAddr != "" {
		startAdminAPI(*adminListenAddr, *adminToken, evaluator)
	}

	// Create the proxy handler with body size limit (H-6 fix)
	handler, err := proxy.New(*upstreamURL, evaluator)
	if err != nil {
		log.Fatalf("invalid upstream URL: %v", err)
	}
	handler.MaxBodyBytes = *maxBodyMB * 1024 * 1024

	// Build main mux — proxy
	mux := http.NewServeMux()
	mux.Handle("/", handler)

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

// requireAdminAuth is HTTP middleware for admin API authentication (C-1 fix).
func requireAdminAuth(expectedToken string, next http.HandlerFunc) http.HandlerFunc {
	if expectedToken == "" {
		// No token configured — allow all (backward compat)
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, `{"error": "authorization required"}`, http.StatusUnauthorized)
			return
		}
		// Support "Bearer <token>" format
		var token string
		if len(auth) > 7 && auth[:7] == "Bearer " {
			token = auth[7:]
		} else {
			token = auth
		}
		// Constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			http.Error(w, `{"error": "invalid authorization token"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// adminMux creates the admin API HTTP mux with all handlers configured.
// Exported for testing — shared between production startAdminAPI and test servers.
func adminMux(token string, eval *compositeEvaluator) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/admin/rules", requireAdminAuth(token, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		eval.mu.RLock()
		cfg := eval.local
		eval.mu.RUnlock()
		if cfg == nil {
			json.NewEncoder(w).Encode(map[string]string{"status": "no config loaded"})
			return
		}
		json.NewEncoder(w).Encode(cfg)
	}))

	mux.HandleFunc("/admin/rules/update", requireAdminAuth(token, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			http.Error(w, "use POST or PUT", http.StatusMethodNotAllowed)
			return
		}
		var newCfg rules.Config
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			http.Error(w, fmt.Sprintf(`{"error": "invalid JSON: %s"}`, err), http.StatusBadRequest)
			return
		}
		if err := rules.Validate(&newCfg); err != nil {
			http.Error(w, fmt.Sprintf(`{"error": "invalid config: %s"}`, err), http.StatusBadRequest)
			return
		}
		eval.mu.Lock()
		eval.local = &newCfg
		eval.mu.Unlock()
		metrics.ConfigReloads.Inc()
		log.Printf("admin API: rules updated (depth=%d fields=%d blocklist=%d)", newCfg.DepthLimit, newCfg.MaxFieldCount, len(newCfg.FieldBlocklist))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))

	mux.HandleFunc("/admin/tenants", requireAdminAuth(token, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if eval.tenants == nil {
			json.NewEncoder(w).Encode([]string{})
			return
		}
		json.NewEncoder(w).Encode(eval.tenants.List())
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
			if eval.tenants == nil {
				json.NewEncoder(w).Encode(map[string]string{"error": "tenant store not available"})
				return
			}
			cfg := eval.tenants.Get(tenantID)
			json.NewEncoder(w).Encode(cfg)

		case http.MethodPost, http.MethodPut:
			var newCfg rules.Config
			if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
				http.Error(w, fmt.Sprintf("invalid JSON: %s", err), http.StatusBadRequest)
				return
			}
			if err := rules.Validate(&newCfg); err != nil {
				http.Error(w, fmt.Sprintf(`{"error": "invalid config: %s"}`, err), http.StatusBadRequest)
				return
			}
			if eval.tenants != nil {
				eval.tenants.Set(tenantID, &newCfg)
				metrics.ActiveTenants.Set(float64(eval.tenants.Count()))
				log.Printf("admin API: tenant %q rules updated", tenantID)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

		case http.MethodDelete:
			if eval.tenants != nil {
				eval.tenants.Delete(tenantID)
				metrics.ActiveTenants.Set(float64(eval.tenants.Count()))
				log.Printf("admin API: tenant %q deleted", tenantID)
			}
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
		}
		if eval.tenants != nil {
			stats["tenants"] = eval.tenants.Count()
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
func startAdminAPI(addr, token string, eval *compositeEvaluator) {
	mux := adminMux(token, eval)

	// Admin server also gets timeouts (H-7 fix)
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

// compositeEvaluator runs local rules first, then tenant-specific rules,
// OPA with caching, then schema validation. Thread-safe for live config reloads.
type compositeEvaluator struct {
	mu            sync.RWMutex
	local         *rules.Config
	tenants       *tenant.Store
	opa           *opa.Client
	schema        *parser.SchemaInfo
	cacheTTL      time.Duration
	cache         map[string]cachedDecision
	opaFailClosed bool
	opaAuditOnly  bool
}

type cachedDecision struct {
	result *rules.Result
	expiry time.Time
}

func (c *compositeEvaluator) Evaluate(info *parser.QueryInfo) (*rules.Result, error) {
	c.mu.RLock()
	localCfg := c.local
	tenants := c.tenants
	schema := c.schema
	opaClient := c.opa
	cacheTTL := c.cacheTTL
	opaFailClosed := c.opaFailClosed
	c.mu.RUnlock()

	// 0. Tenant-specific rules (overrides default config)
	if tenants != nil {
		tenantCfg := tenants.Get(info.TenantID)
		if tenantCfg != nil {
			result := tenantCfg.Evaluate(info)
			if !result.Allowed {
				metrics.RecordBlock(result.Reason)
				return result, nil
			}
		}
	}

	// 1. Operation-name allowlist check (fast path)
	if localCfg != nil && len(localCfg.AllowedOperations) > 0 {
		found := false
		for _, op := range localCfg.AllowedOperations {
			if op == info.OperationType {
				found = true
				break
			}
		}
		if !found {
			result := &rules.Result{Allowed: false, Reason: fmt.Sprintf("operation type %q is not allowed", info.OperationType)}
			metrics.RecordBlock(result.Reason)
			return result, nil
		}
	}

	// 2. Local rules evaluation
	if localCfg != nil {
		result := localCfg.Evaluate(info)
		if !result.Allowed {
			metrics.RecordBlock(result.Reason)
			return result, nil
		}
	}

	// 3. Schema-aware validation
	if schema != nil {
		allowed, reason := schema.Validate(info)
		if !allowed {
			metrics.RecordBlock(reason)
			return &rules.Result{Allowed: false, Reason: reason}, nil
		}
	}

	// 4. OPA evaluation with caching (H-3 fix: better cache key includes field paths)
	if opaClient.Configured() {
		cacheKey := decisionCacheKey(info)
		if cacheTTL > 0 {
			c.mu.RLock()
			if cached, ok := c.cache[cacheKey]; ok && time.Now().Before(cached.expiry) {
				c.mu.RUnlock()
				metrics.RecordOPA("cache_hit")
				if c.opaAuditOnly && !cached.result.Allowed {
					metrics.RecordOPAAuditBlock(cached.result.Reason)
					log.Printf("[AUDIT] OPA would block: %s (allowed in audit-only mode)", cached.result.Reason)
					return &rules.Result{Allowed: true}, nil
				}
				return cached.result, nil
			}
			c.mu.RUnlock()
		}

		result, err := opaClient.Evaluate(info)
		if err != nil {
			metrics.RecordOPA("error")
			if opaFailClosed {
				// C-2 fix: fail closed when configured
				return &rules.Result{Allowed: false, Reason: "OPA unavailable — request blocked for safety"}, nil
			}
			// On OPA error, allow by default (fail open) — backward compat
			return &rules.Result{Allowed: true}, nil
		}

		metrics.RecordOPA("evaluated")
		if !result.Allowed {
			if c.opaAuditOnly {
				metrics.RecordOPAAuditBlock(result.Reason)
				log.Printf("[AUDIT] OPA would block: %s (allowed in audit-only mode)", result.Reason)
				result = &rules.Result{Allowed: true}
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

	return &rules.Result{Allowed: true}, nil
}

// decisionCacheKey builds a cache key from query info.
// H-3 fix: includes a hash of field paths to prevent cache poisoning.
func decisionCacheKey(info *parser.QueryInfo) string {
	// Include operation type, depth, field count, and a hash of field paths
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
	// Return first 8 hex chars
	return fmt.Sprintf("%08x", h)
}
