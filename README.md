# gql-firewall

A **GraphQL firewall sidecar** that intercepts, inspects, and secures GraphQL requests before they reach your upstream server. Built with Go (control plane) and optionally accelerated with Rust (hot-path parser), with OPA/Rego integration for policy-as-code — covering the [OWASP GraphQL Top 10](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html) and common attack vectors.

```
        ┌───────────┐    GraphQL     ┌──────────────┐  rules  ┌─────────┐
 Client ─▶  gql-    │  query/block   │   Upstream   │◀───────▶│  OPA    │
        │  firewall │───────────────▶│   GraphQL    │  eval   │ Sidecar │
        │ sidecar   │    response    │   Server     │         │(optional)│
        └───────────┘               └──────────────┘         └─────────┘
```

## Attack Coverage

gql-firewall's OPA Rego policies (35 tests) cover 12 attack categories — the most comprehensive GraphQL firewall policy set available as open source:

| # | Attack Vector | Detection | Status |
|---|---|---|---|
| 1 | **Introspection Abuse** — `__schema` / `__type` / `__typename` discovery | Blocks exact and nested paths | ✅ |
| 2 | **Depth-based DoS** — Nested query bombs `{a{b{c{...}}}}` | `depth_limit: 10` | ✅ |
| 3 | **Alias-based DoS** — Same field × 500 aliases | `field_count > 100` threshold | ✅ |
| 4 | **Directive-based DoS** — Expensive custom directives | `max_directives: 5` | ✅ |
| 5 | **Batching Attack** — Multiple ops in one request | `max_batch_size: 1` | ✅ |
| 6 | **Unauthorized Field Access** — PII, secrets, admin fields | 12-field blocklist + allowlist | ✅ |
| 7 | **Mutation Abuse** — Subscriptions in prod, unexpected state changes | Operation type restrictions | ✅ |
| 8 | **Argument Injection** — Deeply nested argument objects | `max_argument_depth: 5` | ✅ |
| 9 | **N+1 Abuse** — Excessive list field requests | `max_lists_requested: 5` | ✅ |
| 10 | **Fragment Explosion** — `... on Type` across many unions | `max_fragment_spreads: 15` | ✅ |
| 11 | **Query Cost** — Cheap-to-parse, expensive-to-execute queries | `depth × field_count ≤ 50` budget | ✅ |
| 12 | **Persisted Query Bypass** — Dynamic queries in PQ-only mode | `require_persisted_queries` + hash validation | ✅ |

## CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--listen` | `:8081` | Firewall proxy listen address |
| `--upstream` | `http://localhost:8080` | Upstream GraphQL server |
| `--config` | `config/rules.json` | Path to rules configuration JSON |
| `--schema` | `""` | Path to GraphQL SDL schema (optional) |
| `--opa` | `""` | OPA sidecar endpoint (optional) |
| `--opa-cache-ttl` | `60s` | TTL for cached OPA decisions |
| `--opa-fail-closed` | `false` | Block when OPA is unreachable |
| `--admin` | `:8082` | Admin API listen address (empty = disable) |
| `--admin-token` | `""` | Bearer token for admin API auth |
| `--metrics-listen` | `""` | Separate metrics port (empty = serve on main port) |
| `--tls-cert` | `""` | TLS certificate file path |
| `--tls-key` | `""` | TLS private key file path |
| `--max-body-mb` | `1` | Maximum request body size in MB |

### Security Features

| Feature | Flag / Config | What it prevents |
|---|---|---|
| **Admin API auth** | `--admin-token` | Unauthorized admin API access (C-1) |
| **OPA fail-closed** | `--opa-fail-closed` | Bypass via OPA DoS (C-2) |
| **Config validation** | Built-in | Disabled protections via empty config (C-3) |
| **TLS encryption** | `--tls-cert` + `--tls-key` | Cleartext interception (H-5) |
| **Body size limit** | `--max-body-mb` | OOM via oversized requests (H-6) |
| **Server timeouts** | Built-in | Slow loris / connection exhaustion (H-7) |
| **Tenant key validation** | Via API | Tenant impersonation (H-2) |
| **Sanitized errors** | Built-in | Information disclosure (H-4) |
| **Improved cache key** | Built-in | OPA cache poisoning (H-3) |
| **Metrics isolation** | `--metrics-listen` | Traffic pattern leakage (M-4) |
| **Graceful shutdown** | Built-in | Dropped requests on deploy (M-3) |

### Core
- **GraphQL query parsing** — Parses queries, mutations, and subscriptions using `gqlparser` (Go) or `async-graphql-parser` (Rust). Extracts operation type, name, depth, field count, and full field paths.
- **Configurable rules engine** — JSON-configured rules evaluated before forwarding:
  - **Depth limiting** — Reject queries that nest beyond N levels
  - **Field counting** — Reject queries requesting too many fields
  - **Operation type control** — Allow or block query/mutation/subscription
  - **Operation-name allowlist** — Only allow named operations (e.g. `query GetUser`)
  - **Field allowlists** — Only permit specified field paths
  - **Field blocklists** — Deny specific sensitive fields (takes precedence)
- **OPA/Rego integration** — Optional OPA sidecar for external policy evaluation.
  - **OPA decision caching** — Cache OPA results with configurable TTL (`--opa-cache-ttl`)
  - **Fail-open safety** — On OPA errors, requests pass through (configurable)
- **SDL schema-aware validation** — Accept a GraphQL schema file (`--schema`). Validates requested fields exist on Query type before forwarding.
- **Live admin API** — View and update rules at runtime via REST API on `:8082`.
- **Prometheus metrics** — `/metrics` endpoint with counters for requests, blocks, latency, rule evaluations, and OPA calls.
- **Per-tenant policy isolation** — Each tenant (identified via `X-API-Key` header) can have its own rules configuration. Managed via admin API.
- **Configurable hot-reload** — Watch rule files for changes or update via admin API — both apply without restart.

### Performance
- **Go control plane** — Fast, memory-safe, goroutine-per-request. P99 <5ms with local rules.
- **Rust hot-path parser** (optional) — Runs as an HTTP sidecar using `async-graphql-parser`. Sub-millisecond parsing latency.
- **OPA decision caching** — Avoids redundant OPA calls for repeated query patterns. ~200µs vs ~2ms RPC on cache hit.

### Security
- **12 attack vectors covered** (see table above)
- **Red-team verified** — 30 attack simulation tests across Go proxy, Go parser, and Rust parser. 7 real vulnerabilities found and patched (Content-Type bypass, case-sensitive path bypass, OPA reason injection, tenant ID extraction bug, Rust circular fragment crash, upstream URL validation, Rust HTTP body size).
- **Deny-override model** — requests pass by default, blocked only by matching deny rules (safe for phased rollout)
- **Sensitive field blocking** — SSN, passwords, credit cards, API keys, secrets
- **Introspection blocking** — direct + nested paths
- **Operation restrictions** — per-environment operation type control
- **Query cost budgeting** — Depth × field count complexity budgets
- **Persisted query mode** — block dynamic queries in production
- **Rate limiting** — Via OPA policies with external data integration

### Observability
- **Prometheus `/metrics`** — Exposes request counts (by outcome + operation type), blocked request counters (by rule reason), latency histograms (by outcome), rule evaluation counters, OPA call counters, config reload counters, and active tenant gauge.
- **Structured deny reasons** — Every blocked query returns a machine-readable `"reason"` field.
- **Admin health endpoint** — `GET /admin/health` returns `{"status": "ok"}`, suitable for liveness probes.
- **Admin stats endpoint** — `GET /admin/stats` returns cache size and tenant counts.

## Quick Start

### Prerequisites
- Go 1.23+ (for building)
- Rust 1.75+ (optional, for hot-path parser)
- OPA 1.0+ (optional, for policy evaluation — `opa test opa-policies/` validates)

### Install & Run

```bash
# Clone and build
git clone ... && cd gql-firewall
go build -o gql-firewall ./cmd/server/

# Start with local rules only
./gql-firewall \
  --upstream http://localhost:8080 \
  --config ./config/rules.json \
  --listen :8081

# With all optional features enabled
./gql-firewall \
  --upstream http://localhost:8080 \
  --config ./config/rules.json \
  --schema ./schema.graphql \
  --listen :8081 \
  --admin :8082 \
  --opa http://localhost:8181/v1/data/graphql/deny \
  --opa-cache-ttl 60s

# With Rust hot-path parser sidecar
./rust-parser/target/release/gql-parser --listen 9090 &
./gql-firewall --upstream http://localhost:8080 --listen :8081
```

### Test It

```bash
# Valid query (should pass)
curl -X POST http://localhost:8081/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ hello }"}'

# Deep query (blocked by depth limit = 10)
curl -X POST http://localhost:8081/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ a { b { c { d { e { f } } } } } }"}'

# Sensitive field (blocked by field blocklist)
curl -X POST http://localhost:8081/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user { name ssn } }"}'

# Introspection (blocked by OPA policy if deployed)
curl -X POST http://localhost:8081/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'

# Blocked operation type
curl -X POST http://localhost:8081/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "subscription OnMsg { messageAdded { id } }"}'
```

## Configuration

### Rules JSON

Create a JSON file with the rules you want to enforce:

```json
{
  "depth_limit": 10,
  "max_field_count": 100,
  "blocked_operations": ["subscription"],
  "field_blocklist": ["__schema", "__type", "user.ssn", "user.password", "user.creditCard"]
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `depth_limit` | int | 0 | Max query nesting depth. 0 = disabled |
| `max_field_count` | int | 0 | Max fields per query. 0 = disabled |
| `blocked_operations` | []string | [] | Operation types to block (e.g. "mutation") |
| `allowed_operations` | []string | [] | Only allow these operation types |
| `field_allowlist` | []string | [] | Only allow these field paths |
| `field_blocklist` | []string | [] | Block these field paths (overrides allowlist) |

### OPA Policies

The `opa-policies/` directory contains production-ready Rego policy templates:

```bash
# Deploy to OPA sidecar
curl -X PUT --data-binary @opa-policies/graphql.rego \
  http://localhost:8181/v1/policies/graphql

# Debug: evaluate a specific query
echo '{"input": {"depth": 5, "field_count": 3, "operation_type": "query", "field_paths": ["user", "user.name"]}}' | \
  opa eval --data opa-policies/graphql.rego --input-file - "data.graphql"

# Run all policy tests
opa test opa-policies/ -v
```

The OPA input schema matches the Go parser's `QueryInfo` structure:

```json
{
  "input": {
    "operation_type": "query",
    "operation_name": "GetUser",
    "depth": 3,
    "field_count": 5,
    "field_paths": ["user", "user.name", "user.email"],
    "batch_size": 1,
    "argument_depth": 2,
    "lists_requested": 1,
    "fragment_spread_count": 0,
    "directives": 0,
    "require_persisted_queries": false,
    "field_allowlist": []
  }
}
```

## Admin API

The admin API runs on a separate port (`:8082` by default). Use it for live rule management without restarting the sidecar.

| Endpoint | Method | Description |
|---|---|---|
| `GET /admin/health` | GET | Health check — returns `{"status": "ok"}` |
| `GET /admin/rules` | GET | Returns current rules configuration |
| `PUT /admin/rules/update` | POST/PUT | Update rules at runtime (accepts full `rules.Config` JSON) |
| `GET /admin/stats` | GET | Returns runtime statistics (cache size, tenant count) |

| `GET /admin/tenants` | GET | List all configured tenant IDs |
| `GET /admin/tenants/{id}` | GET | Get a specific tenant's rules config |
| `POST /admin/tenants/{id}` | POST/PUT | Create or update a tenant's rules |
| `DELETE /admin/tenants/{id}` | DELETE | Remove a tenant's rules (falls back to default) |

```bash
# View current rules
curl http://localhost:8082/admin/rules

# Update rules at runtime
curl -X POST http://localhost:8082/admin/rules/update \
  -H "Content-Type: application/json" \
  -d '{"depth_limit": 5, "max_field_count": 50}'

# Create tenant-specific rules (tenant ID extracted from "myapp_..." API key)
curl -X PUT http://localhost:8082/admin/tenants/myapp \
  -H "Content-Type: application/json" \
  -d '{"depth_limit": 3}'

# List tenants
curl http://localhost:8082/admin/tenants

# Delete tenant
curl -X DELETE http://localhost:8082/admin/tenants/myapp

# Health check
curl http://localhost:8082/admin/health

# Stats
curl http://localhost:8082/admin/stats
```

## Metrics

Prometheus metrics are exposed at `/metrics` on the main listen port. Metrics include:

| Metric | Type | Labels | Description |
|---|---|---|---|
| `gql_firewall_requests_total` | Counter | `outcome`, `operation_type` | Total GraphQL requests |
| `gql_firewall_requests_blocked_total` | Counter | `reason` | Blocked requests by rule reason |
| `gql_firewall_request_duration_seconds` | Histogram | `outcome` | Pipeline latency |
| `gql_firewall_active_tenants` | Gauge | — | Active tenant count |
| `gql_firewall_rule_evaluations_total` | Counter | `rule` | Rule evaluation count |
| `gql_firewall_config_reloads_total` | Counter | — | Config hot-reload count |
| `gql_firewall_opa_requests_total` | Counter | `outcome` | OPA sidecar call count |

```bash
# Scrape metrics
curl http://localhost:8081/metrics
```

## Architecture

```
Request Flow
════════════

┌────────────────────────────────────────────────────────────┐
│  Client                                                     │
│  POST /graphql {"query": "..."}                             │
└─────────┬──────────────────────────────────────────────────┘
          │
          ▼
┌────────────────────────────────────────────────────────────┐
│  gql-firewall sidecar  (Go)                                 │
│                                                             │
│  1. Parse GraphQL body (JSON)                                │
│  2. Parse GraphQL query (AST)                                │
│     │                                    ┌───────────────┐  │
│     ├── Optional: Rust hot-path parser──▶│ gql-parser    │  │
│     │   (if sidecar available)           │ (Rust, :9090) │  │
│     │                                    └───────────────┘  │
│  3. Evaluate local rules (depth, fields, ops)                │
│  4. Evaluate OPA sidecar (optional)                          │
│     │                                    ┌───────────────┐  │
│     └───────────────────────────────────▶│ OPA           │  │
│                                          │ (:8181)       │  │
│                                          └───────────────┘  │
│  5. Forward or block?                                        │
└─────────┬──────────────────────────────────────────────────┘
          │                    ┌──── Blocked ────▶ 403 {error, reason}
          ▼                    │
┌────────────────────┐         │
│  Upstream GraphQL  │         │
│  Server            │         │
└────────────────────┘         │
          │                    │
          ▼                    ▼
     200 {data}           403 {"error": "request blocked",
                              "reason": "query depth exceeded limit"}
```

## Project Structure

```
gql-firewall/
├── cmd/server/main.go            # Entry point — wires everything together (+ test, 33 tests)
├── config/rules.json             # Sample firewall rules
├── internal/
│   ├── parser/                   # GraphQL query analysis (37 tests, including 13 invalid-input tests)
│   ├── rules/                    # Configurable rule evaluation (27 tests)
│   ├── config/                   # JSON config loader (7 tests)
│   ├── metrics/                  # Prometheus instrumentation (5 tests)
│   ├── opa/                      # OPA sidecar client (7 tests)
│   ├── proxy/                    # HTTP reverse proxy (29 tests, including 14 red-team attack tests)
│   ├── tenant/                   # Per-tenant rules isolation (11 tests)
│   └── integration/              # End-to-end pipeline tests (9 tests)
├── rust-parser/                  # Rust hot-path parser (8 tests, with circular fragment protection)
│   ├── Cargo.toml
│   └── src/main.rs              # CLI + HTTP sidecar
├── opa-policies/                 # OWA Rego policy templates
│   ├── graphql.rego              # 12 attack categories covered
│   └── graphql_test.rego         # 35 policy tests
├── README.md
├── go.mod / go.sum
└── .gitignore
```

## Test Suite

```
Go:           165 tests — server(33), parser(37), proxy(29), rules(27), tenant(11),
                    integration(9), config(7), opa(7), metrics(5)
Rust:          8 tests  — parsing, depth, fields, paths, mutations, errors, circular fragments
OPA/Rego:     35 tests  — 12 attack categories, edge cases, combined rules
Total:       208 tests  — all passing
```

```bash
# Run everything
go test ./... -count=1
cd rust-parser && cargo test && cd ..
opa test opa-policies/
```

---

## Suggested New Features

The following features align with the product's business model — a standalone GraphQL firewall for mid-market API teams, Go control plane + Rust hot path, with OPA-based policy and an eventual acquisition path to Datadog, Kong, or Cloudflare.

### Near-term (Phase 1 — build on existing architecture)

**1. Prometheus metrics endpoint** — Expose deny counters, latency histograms, and active tenant counts as Prometheus `/metrics`. This is the single most requested feature by mid-market platform teams monitoring their APIs. It also directly feeds into Datadog's agent, making the product immediately useful to Datadog's install base (exit path alignment).

**2. GraphQL schema-aware validation** — Accept an SDL schema file (`--schema schema.graphql`). Use it to detect queries requesting fields that don't exist, arguments of the wrong type, or deprecated fields. This turns the firewall from a generic rate-limiter into a GraphQL-aware security tool — the key differentiator against Kong's generic Lua plugins.

**3. Operation-name-based allowlist** — Allow only known operation names in production (e.g. `query GetUser { ... }` but block arbitrary unnamed queries). This prevents attackers from probing the API surface with anonymous queries. Already partially supported by the OPA `require_persisted_queries` mode — wire it through the Go sidecar config.

### Mid-term (Phase 2 — premium tier enablers)

**4. Per-tenant isolation with Rust hot-path routing** — Route requests to tenant-specific OPA data bundles based on API key or JWT claims. Each tenant gets their own policy scope without deploying separate sidecars. This is the product moat that differentiates from generic API gateways.

**5. Rego policy caching in the Go sidecar** — Cache OPA decisions locally with a TTL to avoid the network hop on repeat queries. For a typical mid-market GraphQL API, ~70% of query patterns repeat within a 60-second window. This brings P99 latency from ~2ms (OPA RPC) to ~200µs (local cache hit). The Rust hot-path parser makes this even faster.

**6. REST API for live rule management** — Add admin endpoints (`POST /admin/rules`, `GET /admin/stats`) so platform teams can update rules without file access or sidecar restarts. This is a table-stakes enterprise feature that enables the Silver/Gold tier pricing model ($15K-$40K/mo).

### Long-term (Phase 3 — acquisition value)

**7. Datadog native integration** — Ship a Datadog Integration tile with out-of-the-box dashboards (blocked queries by rule, latency heatmaps, tenant-level cost attribution). This is the single highest-leverage feature for the Datadog acquisition path — it removes the "integration cost" objection from due diligence.

**8. GraphQL cost analysis engine** — Replace the simple `depth × field_count` heuristic with schema-aware cost weights (per-resolver cost, list size multipliers, join complexity). Expose cost budgets per API key. This moves the product from "WAF for GraphQL" to "cost management platform" — a higher-value category.

**9. Kong/Konnect plugin packaging** — Package the Go sidecar as a Kong plugin (Go PDK) to capture the 30% of the market running Kong. This doesn't change the architecture — it's a deployment packaging change — but it opens the Kong acquisition path.

**10. AI firewall extension** — Integrate a BERT-sized prompt injection classifier (e.g. `laiyer/deberta-v3-base-prompt-injection`) via the Rust hot-path parser using `candle` or `ort`. Run inference at <5ms per query. This turns the product into a GraphQL+AI security platform — the Platinum tier at $100K/mo — and addresses the fastest-growing enterprise security concern.

## Deployment

### Docker

```dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o gql-firewall ./cmd/server/

FROM alpine:3.20
COPY --from=builder /app/gql-firewall /usr/local/bin/
COPY config/rules.json /etc/gql-firewall/rules.json
EXPOSE 8081
ENTRYPOINT ["gql-firewall", "--upstream", "http://upstream:8080", "--config", "/etc/gql-firewall/rules.json", "--listen", ":8081"]
```

### Kubernetes Sidecar

```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: graphql
          image: my-graphql-server:latest
          ports:
            - containerPort: 8080
        - name: gql-firewall
          image: gql-firewall:latest
          args:
            - --upstream=http://localhost:8080
            - --config=/etc/gql-firewall/rules.json
            - --listen=:8081
          ports:
            - containerPort: 8081
          volumeMounts:
            - name: rules
              mountPath: /etc/gql-firewall
      volumes:
        - name: rules
          configMap:
            name: gql-firewall-rules
```

## Development

### Adding a New Rule

1. Add the field to `internal/rules/rules.go` Config struct
2. Add evaluation logic to `Config.Evaluate()` method
3. Write tests in `internal/rules/rules_test.go`
4. Add the Rego deny rule in `opa-policies/graphql.rego`
5. Write Rego test in `opa-policies/graphql_test.rego`

### Adding a New OPA Attack Detection

1. Add the deny rule to `opa-policies/graphql.rego` with a unique message
2. Write test cases in `opa-policies/graphql_test.rego`
3. Validate with `opa test opa-policies/`

## Roadmap

| Phase | Timeline | Features | Revenue |
|---|---|---|---|
| **Phase 1** | Months 0-6 | Prometheus, schema-aware validation, operation-name allowlist | $99-499/mo |
| **Phase 2** | Months 6-12 | Per-tenant isolation, policy caching, live admin API | $1,999-9,999/mo |
| **Phase 3** | Months 12-24 | Datadog integration, cost analysis engine, Kong packaging, AI firewall | $40-100K/mo |

## License

MIT
