// gql-firewall — GraphQL firewall sidecar.
package main

import (
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

func main() {
	var (
		listenAddr      = flag.String("listen", ":8081", "Address to listen on")
		upstreamURL     = flag.String("upstream", "http://localhost:8080", "Upstream GraphQL server URL")
		configPath      = flag.String("config", "config/rules.json", "Path to rules configuration JSON file")
		opaEndpoint     = flag.String("opa", "", "OPA sidecar endpoint (optional)")
		schemaPath      = flag.String("schema", "", "Path to GraphQL SDL schema file (optional)")
		configReload    = flag.Bool("watch", true, "Watch config file for hot-reload")
		adminListenAddr = flag.String("admin", ":8082", "Admin API listen address (set to empty to disable)")
		cacheTTL        = flag.Duration("opa-cache-ttl", 60*time.Second, "TTL for cached OPA decisions (0 = disabled)")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("gql-firewall v0.2.0 starting (listen=%s upstream=%s)", *listenAddr, *upstreamURL)

	// Load local rules configuration
	rulesCfg := &rules.Config{}
	if *configPath != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			log.Fatalf("failed to load config: %v", err)
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

	// Start config file watcher for hot-reload
	configUpdates := make(chan *rules.Config, 1)
	if *configReload && *configPath != "" {
		updates, err := config.Watch(*configPath)
		if err != nil {
			log.Fatalf("failed to start config watcher: %v", err)
		}
		go func() {
			for newCfg := range updates {
				rulesCfg = newCfg
				metrics.ConfigReloads.Inc()
				log.Printf("config hot-reloaded from %s", *configPath)
			}
		}()
	} else {
		// Push initial config so admin API can read it
		configUpdates <- rulesCfg
	}

	// Set up OPA client (optional)
	opaClient := opa.New(*opaEndpoint)
	if *opaEndpoint != "" {
		log.Printf("OPA sidecar configured at %s (cache TTL: %s)", *opaEndpoint, *cacheTTL)
	} else {
		log.Printf("no OPA endpoint configured — using local rules only")
	}

	// Build the composite evaluator: local rules → tenant config → caching OPA → schema
	tenantStore := tenant.New(rulesCfg)

	evaluator := &compositeEvaluator{
		local:       rulesCfg,
		tenants:     tenantStore,
		opa:         opaClient,
		schema:      schemaDoc,
		cacheTTL:    *cacheTTL,
	}

	// Set up the admin API for live rule management
	if *adminListenAddr != "" {
		startAdminAPI(*adminListenAddr, evaluator, configUpdates)
	}

	// Create the proxy handler
	handler := proxy.New(*upstreamURL, evaluator)

	// Build main mux — proxy + metrics
	mux := http.NewServeMux()
	mux.Handle("/", handler)
	mux.Handle("/metrics", metrics.Handler())

	server := &http.Server{Addr: *listenAddr, Handler: mux}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down...")
		server.Close()
	}()

	log.Printf("listening on %s (metrics at /metrics)", *listenAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

// startAdminAPI starts the admin HTTP server for live rule management.
func startAdminAPI(addr string, eval *compositeEvaluator, configUpdates <-chan *rules.Config) {
	mux := http.NewServeMux()

	// GET /admin/rules — returns current rules configuration
	mux.HandleFunc("/admin/rules", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		eval.mu.RLock()
		cfg := eval.local
		eval.mu.RUnlock()
		json.NewEncoder(w).Encode(cfg)
	})

	// PUT /admin/rules — updates rules configuration at runtime
	mux.HandleFunc("/admin/rules/update", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			http.Error(w, "use POST or PUT", http.StatusMethodNotAllowed)
			return
		}
		var newCfg rules.Config
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			http.Error(w, fmt.Sprintf("invalid JSON: %s", err), http.StatusBadRequest)
			return
		}
		eval.mu.Lock()
		eval.local = &newCfg
		eval.mu.Unlock()
		metrics.ConfigReloads.Inc()
		log.Printf("admin API: rules updated")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// GET /admin/tenants — lists all configured tenants
	mux.HandleFunc("/admin/tenants", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if eval.tenants == nil {
			json.NewEncoder(w).Encode([]string{})
			return
		}
		json.NewEncoder(w).Encode(eval.tenants.List())
	})

	// PUT /admin/tenants/{id} — create or update a tenant's rules
	mux.HandleFunc("/admin/tenants/", func(w http.ResponseWriter, r *http.Request) {
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
	})

	// GET /admin/stats — returns runtime statistics
	mux.HandleFunc("/admin/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		stats := map[string]interface{}{
			"cache_entries": 0,
			"tenants":       1,
		}
		if eval.cache != nil {
			eval.mu.RLock()
			stats["cache_entries"] = len(eval.cache)
			eval.mu.RUnlock()
		}
		if eval.tenants != nil {
			stats["tenants"] = eval.tenants.Count()
		}
		json.NewEncoder(w).Encode(stats)
	})

	// GET /admin/health — simple health check
	mux.HandleFunc("/admin/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	go func() {
		log.Printf("admin API listening on %s", addr)
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Printf("admin API error: %v", err)
		}
	}()
}

// compositeEvaluator runs local rules first, then tenant-specific rules,
// OPA with caching, then schema validation. Thread-safe for live config reloads.
type compositeEvaluator struct {
	mu       sync.RWMutex
	local    *rules.Config
	tenants  *tenant.Store
	opa      *opa.Client
	schema   *parser.SchemaInfo
	cacheTTL time.Duration
	cache    map[string]cachedDecision
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

	// 4. OPA evaluation with caching
	if opaClient.Configured() {
		cacheKey := decisionCacheKey(info)
		if cacheTTL > 0 {
			c.mu.RLock()
			if cached, ok := c.cache[cacheKey]; ok && time.Now().Before(cached.expiry) {
				c.mu.RUnlock()
				metrics.RecordOPA("cache_hit")
				return cached.result, nil
			}
			c.mu.RUnlock()
		}

		result, err := opaClient.Evaluate(info)
		if err != nil {
			metrics.RecordOPA("error")
			// On OPA error, allow by default (fail open)
			return &rules.Result{Allowed: true}, nil
		}

		metrics.RecordOPA("evaluated")
		if !result.Allowed {
			metrics.RecordBlock(result.Reason)
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

// decisionCacheKey builds a cache key from query info for repeated pattern matching.
func decisionCacheKey(info *parser.QueryInfo) string {
	// Use operation type + depth + field count as a lightweight cache key
	return fmt.Sprintf("%s|%d|%d", info.OperationType, info.Depth, info.FieldCount)
}
