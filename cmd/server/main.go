// gql-firewall is a GraphQL firewall sidecar that intercepts GraphQL requests,
// parses them, evaluates configurable rules, and optionally queries an OPA
// sidecar for policy decisions. It forwards allowed requests to the upstream
// GraphQL server and blocks disallowed ones with a 403 response.
//
// Usage:
//
//	gql-firewall \
//	  --upstream http://localhost:8080 \
//	  --config ./config/rules.json \
//	  --listen :8081 \
//	  --opa http://localhost:8181/v1/data/graphql/allow
//
// The --opa flag is optional — without it, only the local rules apply.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/monch1962/gql-firewall/internal/config"
	"github.com/monch1962/gql-firewall/internal/opa"
	"github.com/monch1962/gql-firewall/internal/parser"
	"github.com/monch1962/gql-firewall/internal/proxy"
	"github.com/monch1962/gql-firewall/internal/rules"
)

func main() {
	var (
		listenAddr  = flag.String("listen", ":8081", "Address to listen on")
		upstreamURL = flag.String("upstream", "http://localhost:8080", "Upstream GraphQL server URL")
		configPath  = flag.String("config", "", "Path to rules configuration JSON file")
		opaEndpoint = flag.String("opa", "", "OPA sidecar endpoint (optional)")
		configReload = flag.Bool("watch", true, "Watch config file for changes and hot-reload")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("gql-firewall starting (listen=%s upstream=%s)", *listenAddr, *upstreamURL)

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

	// Start config file watcher for hot-reload
	if *configReload && *configPath != "" {
		updates, err := config.Watch(*configPath)
		if err != nil {
			log.Fatalf("failed to start config watcher: %v", err)
		}
		go func() {
			for newCfg := range updates {
				rulesCfg = newCfg
				log.Printf("config hot-reloaded from %s", *configPath)
			}
		}()
	}

	// Set up OPA client (optional)
	opaClient := opa.New(*opaEndpoint)
	if *opaEndpoint != "" {
		log.Printf("OPA sidecar configured at %s", *opaEndpoint)
	} else {
		log.Printf("no OPA endpoint configured — using local rules only")
	}

	// Composite evaluator: checks local rules first, then OPA
	evaluator := &compositeEvaluator{
		local: rulesCfg,
		opa:   opaClient,
	}

	// Create the proxy handler
	handler := proxy.New(*upstreamURL, evaluator)

	// Start HTTP server
	server := &http.Server{
		Addr:    *listenAddr,
		Handler: handler,
	}

	// Graceful shutdown on SIGINT/SIGTERM
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down...")
		server.Close()
	}()

	log.Printf("listening on %s", *listenAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

// compositeEvaluator runs local rules first, then checks OPA if the query
// passes local rules. This gives fast local rejection without an OPA call.
type compositeEvaluator struct {
	local *rules.Config
	opa   *opa.Client
}

func (c *compositeEvaluator) Evaluate(info *parser.QueryInfo) (*rules.Result, error) {
	// Check local rules first (fast path, no network call)
	if c.local != nil {
		result := c.local.Evaluate(info)
		if !result.Allowed {
			return result, nil
		}
	}

	// If OPA is configured, check it too
	if c.opa != nil {
		return c.opa.Evaluate(info)
	}

	return &rules.Result{Allowed: true}, nil
}
