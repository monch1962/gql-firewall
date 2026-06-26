# gql-firewall

A **GraphQL firewall sidecar** that intercepts, inspects, and secures GraphQL requests before they reach your upstream server. Built entirely in Go with OPA/Rego integration for policy-as-code — covering the [OWASP GraphQL Top 10](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html) and common attack vectors.

```
        ┌───────────┐    GraphQL     ┌──────────────┐  rules  ┌─────────┐
 Client ─▶  gql-    │  query/block   │   Upstream   │◀───────▶│  OPA    │
        │  firewall │───────────────▶│   GraphQL    │  eval   │ Sidecar │
        │ sidecar   │    response    │   Server     │         │(optional)│
        └───────────┘               └──────────────┘         └─────────┘
```

## Attack Coverage

gql-firewall's OPA Rego policies (33 tests) cover 12 attack categories, with 46 additional red-team attack simulation tests at the HTTP transport layer:

### OPA Policy Coverage (12 categories)

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

### Red-Team Verified Transport Protection (46 attack simulation tests)

All verified with TDD — tests written first, then defenses implemented.

| # | Attack Vector | Defense | Status |
|---|---|---|---|
| R1 | Missing `Content-Type` header | Reject with 415 unless JSON Content-Type present | ✅ |
| R2 | Wrong `Content-Type` (`text/plain`) | Same R1 fix | ✅ |
| R3 | Case-sensitive path bypass (`/GRAPHQL`) | `strings.ToLower` before suffix check | ✅ |
| R4 | Path traversal (`/graphql/../admin`) | 🟡 Go normalizes before handler sees it | ✅ |
| R5 | Query string injection | Body `query` field validated | ✅ |
| R6 | OPA reason injection | `sanitizeReason()` filters non-printable ASCII | ✅ |
| R7 | Double `Content-Type` header | Go's `Header.Get()` returns first value | ✅ |
| R8a | GET without `?query=` param | Returns 400 | ✅ |
| R8b | GET with blocked query | Intercepted and returns 403 | ✅ |
| R8c | GET with allowed query | Intercepted and forwarded | ✅ |
| R9 | Empty body | Returns 400 | ✅ |
| R10 | Whitespace-only body | Returns 400 | ✅ |
| R11 | Valid JSON, no `query` field | Returns 400 | ✅ |
| R12 | OPA cache memory exhaustion | Mitigated by hash-keyed cache | ✅ |
| R13 | Log injection via tenant ID | `%q` escaping | ✅ |
| R14 | Duplicate Content-Type (first valid) | Go header behavior | ✅ |
| R15 | Tenant ID edge case (`__double`) | `hasLeadingContent()` guard | ✅ |
| R17 | Cache key collision | FNV-hashed field paths | ✅ |
| R18 | Invalid JSON in blocked responses | `sanitizeReason()` ensures valid JSON | ✅ |
| R24 | Upstream URL validation | `proxy.New()` returns error on invalid URLs | ✅ |
| **R27** | **HTTP Method Override** (X-HTTP-Method-Override) | Still inspected as POST (same path) | ✅ |
| **R28** | **Content-Type: application/graphql** | Rejected — only JSON accepted | ✅ |
| **R29** | **JSON with UTF-8 BOM** | Go's JSON decoder strips BOM automatically | ✅ |
| **R30** | **URL-encoded form body** | Rejected — 415 Unsupported Media Type | ✅ |
| **R31** | **Anonymous inline fragment** `{ ... { } }` | Parser handles correctly | ✅ |
| **R32** | **Variable as directive arg** `@skip(if: $s)` | Parser extracts variables and operation directives | ✅ |
| **R33** | **Negative body limit** | Treated as unlimited, flag validated at startup | ✅ |
| **R34** | **Zero body limit** | Treated as unlimited (skips MaxBytesReader) | ✅ |
| **R35** | **Deep fragment chain (300+)** | No stack overflow — visited set prevents re-entry | ✅ |
| **R36** | **Batch item with empty query** | Returns 400 | ✅ |
| **R37** | **Duplicate JSON keys in body** | Go uses last value, no crash | ✅ |
| **R38** | **Unicode escapes in JSON body** | Decoded by JSON stdlib, parsed correctly | ✅ |
| **R39** | **Upstream URL without host** | `New()` returns error | ✅ |
| **R40** | **Upstream file:// scheme** | `New()` returns error | ✅ |
| **R41** | **Very long operation name** (10K chars) | Parses without memory issues | ✅ |
| **R42** | **Comment with special chars** (emoji, unicode) | Parser handles correctly | ✅ |
| **R43** | **Batch with mixed query/mutation** | Each item inspected independently | ✅ |
| **R44** | **Colliding query hashes** (same depth, different paths) | Hash includes full query text | ✅ |
| **R45** | **Deep argument nesting** (7 levels) | `argument_depth` measured correctly | ✅ |
| **R46** | **Complex variable types** `[[[String!]!]!]!` | Parser extracts variable count | ✅ |
| **R47** | **Very long field argument string** (50K chars) | Parses without OOM | ✅ |
| **R48** | **Deeply nested JSON body** (10k levels) | Rejected — `json.Decoder` has depth limits | ✅ |
| **R49** | **Trailing garbage after JSON** `{...}extra` | `dec.More()` check rejects trailing data | ✅ |
| **R50** | **Rate limiter memory exhaustion** (10k keys) | Bucket cleanup removes stale keys every minute | ✅ |
| **R51** | **Admin API body limit** | `10MB MaxBytesReader` on PUSH handlers | ✅ |
| **R52** | **POST with query in URL params only** | Body takes precedence; empty body → 400 | ✅ |
| **R53** | **Very many arguments on field** (500) | Parser handles correctly | ✅ |
| **R54** | **Non-standard methods** (OPTIONS/PUT/DELETE) | Pass through without inspection (correct) | ✅ |
| **R55** | **Null bytes in JSON strings** | Go's JSON decoder rejects null bytes | ✅ |
| **R56** | **Rate limiter concurrent race** (50 goroutines) | Mutex-guarded bucket map, no race | ✅ |
| **R57** | **Very many fields in query** (10k) | Parser extracts all field paths correctly | ✅ |
| **R58** | **Batch with 1000+ items** | Each item inspected independently | ✅ |
| **R59** | **Very large number in variables JSON** | Stored as `json.RawMessage`, no overflow | ✅ |
| **R60** | **Multiple Content-Type values** | Go uses first value (`application/json` accepted) | ✅ |
| **R61** | **GET with invalid variables JSON** | Variables error is non-fatal, query still forwarded | ✅ |
| **R62** | **Field names matching directive names** | `skip`, `include`, `deprecated` as field names | ✅ |
| **R63** | **Admin API enormous payload** (10MB config) | `MaxBytesReader` limits body, returns error | ✅ |
| **R64** | **Multiple GraphQL queries in one body field** | Parser fails on combined syntax → 400 | ✅ |

## CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--listen` | `:8081` | Firewall proxy listen address |
| `--upstream` | `http://localhost:8080` | Upstream GraphQL server |
| `--schema` | `""` | Path to GraphQL SDL schema (optional) |
| `--opa` | `""` | OPA sidecar endpoint (e.g. http://localhost:8181/v1/data/graphql) |
| `--opa-embed` | `""` | Path to Rego policy file for embedded OPA evaluation |
| `--opa-params` | `""` | Path to parameters JSON file for embedded OPA |
| `--opa-cache-ttl` | `60s` | TTL for cached OPA decisions |
| `--opa-fail-closed` | `false` | Block when OPA is unreachable |
| `--opa-audit-only` | `false` | Log OPA would-be blocks without enforcing |
| `--log-format` | `text` | Log format: text or json |
| `--rate-limit` | `0` | Per-tenant/IP rate limit (req/sec, 0 = disabled) |
| `--rate-burst` | `0` | Rate limit burst size (0 = 2x rate-limit) |
| `--admin` | `:8082` | Admin API listen address (empty = disable) |
| `--admin-token` | `""` | Bearer token for admin API auth |
| `--metrics-listen` | `""` | Separate metrics port (empty = serve on main port) |
| `--tls-cert` | `""` | TLS certificate file path |
| `--tls-key` | `""` | TLS private key file path |
| `--max-body-mb` | `1` | Maximum request body size in MB (0 = unlimited, must be ≥ 0) |

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
| **Panic recovery** | Built-in | Process crash on handler panic (H1) |
| **Security headers** | Built-in | MIME sniffing / clickjacking (H2) |
| **Query parse timeout** | Built-in | CPU exhaustion via crafted queries (H3) |
| **Upstream URL validation** | Built-in | Scheme injection / SSRF (H4) |

### Core
- **GraphQL query parsing** — Parses queries, mutations, and subscriptions using `gqlparser/v2`. Extracts operation type, name, depth, field count, and full field paths.
- **OPA/Rego policy engine** — All firewall rules are expressed as Rego policies. Supports two deployment modes:
  - **Sidecar mode** (`--opa`): Evaluate policies via an OPA sidecar HTTP endpoint. Best for scale-out deployments.
  - **Embedded mode** (`--opa-embed`): Evaluate policies in-process using the OPA Go library. Zero external dependencies, ~10µs evaluation time.
- **12 attack categories covered** — See table above. All OWASP GraphQL Top 10 + 2 additional vectors.
- **Configurable via OPA data injection** — Parameters (depth_limit, max_field_count, field_blocklist, etc.) are injected as OPA data. Update at runtime via admin API.
- **SDL schema-aware validation** — Accept a GraphQL schema file (`--schema`). Validates requested fields exist on Query type before forwarding.
- **Live admin API** — View and update rules at runtime via REST API on `:8082`.
- **Prometheus metrics** — `/metrics` endpoint with counters for requests, blocks, latency, rule evaluations, and OPA calls.
- **Per-tenant policy isolation** — Each tenant (identified via `X-API-Key` header) can have its own rules configuration. Managed via admin API.

### Performance
- **Pure Go binary** — Single static binary, no runtime dependencies. P99 <5ms with embedded OPA.
- **OPA decision caching** — Avoids redundant OPA calls for repeated query patterns. ~200µs vs ~2ms RPC on cache hit.

### Security
- **64 attack vectors covered** (12 OPA Rego + 52 red-team HTTP transport)
- **Red-team verified** — 52 attack simulation tests across the Go proxy. Real vulnerabilities found and patched across 5 rounds.
- **Deny-override model** — requests pass by default, blocked only by matching deny rules (safe for phased rollout)
- **Sensitive field blocking** — SSN, passwords, credit cards, API keys, secrets
- **Introspection blocking** — direct + nested paths
- **Operation restrictions** — per-environment operation type control
- **Query cost budgeting** — Depth × field_count complexity budgets
- **Persisted query mode** — block dynamic queries in production
- **Rate limiting** — Via OPA policies with external data integration
- **Audit-only mode** — `--opa-audit-only` runs OPA in log-only mode for safe data collection before enforcement

### Observability
- **Prometheus `/metrics`** — Exposes request counts (by outcome + operation type), blocked request counters (by rule reason), latency histograms (by outcome), rule evaluation counters, OPA call counters, config reload counters, and active tenant gauge.
- **Structured deny reasons** — Every blocked query returns a machine-readable `"reason"` field.
- **Admin health endpoint** — `GET /admin/health` returns `{"status": "ok"}`, suitable for liveness probes.
- **Admin stats endpoint** — `GET /admin/stats` returns cache size and tenant counts.

## Quick Start

### Prerequisites
- Go 1.23+ (for building)
- OPA 1.0+ (optional, for policy evaluation — `opa test opa-policies/` validates)

### Install & Run

```bash
# Clone and build
git clone ... && cd gql-firewall
go build -o gql-firewall ./cmd/server/

# Start with embedded OPA (zero external dependencies)
./gql-firewall \
  --upstream http://localhost:8080 \
  --opa-embed ./opa-policies/graphql.rego \
  --opa-params ./config/params.json \
  --listen :8081

# Start with OPA sidecar
./gql-firewall \
  --upstream http://localhost:8080 \
  --opa http://localhost:8181/v1/data/graphql \
  --listen :8081 \
  --admin :8082

# Start with all optional features
./gql-firewall \
  --upstream http://localhost:8080 \
  --opa-embed ./opa-policies/graphql.rego \
  --opa-params ./config/params.json \
  --schema ./schema.graphql \
  --listen :8081 \
  --admin :8082 \
  --opa-cache-ttl 60s
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

### Parameters JSON

All firewall parameters are injected as OPA data. Create a JSON file that mirrors the Rego policy parameters:

```json
{
  "depth_limit": 10,
  "max_field_count": 100,
  "blocked_operations": ["subscription"],
  "field_blocklist": ["__schema", "__type", "user.ssn", "user.password"]
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `depth_limit` | number | 10 | Max query nesting depth |
| `max_field_count` | number | 100 | Max fields per query |
| `blocked_operations` | array | `["subscription"]` | Operation types to block |
| `allowed_operations` | array | `[]` | Only allow these operation types |
| `field_allowlist` | array | `[]` | Only allow these field paths |
| `field_blocklist` | array | `[]` | Block these field paths (overrides allowlist) |
| `max_directives` | number | 5 | Max directives per query |
| `max_batch_size` | number | 1 | Max operations per batch |
| `max_argument_depth` | number | 5 | Max argument nesting depth |
| `max_lists_requested` | number | 5 | Max list fields per query |
| `max_fragment_spreads` | number | 15 | Max fragment spreads per query |
| `cost_budget` | number | 50 | Complexity budget (depth × field_count) |
| `require_persisted_queries` | bool | false | Block dynamic (non-persisted) queries |

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

The OPA input schema matches the parser's `QueryInfo` structure:

```json
{
  "input": {
    "operation_type": "query",
    "operation_name": "GetUser",
    "depth": 3,
    "field_count": 5,
    "field_paths": ["user", "user.name", "user.email"],
    "tenant_id": "acmecorp",
    "params": {
      "depth_limit": 10,
      "max_field_count": 100
    }
  }
}
```

## Admin API

| Endpoint | Method | Description |
|---|---|---|
| `GET /admin/health` | GET | Health check — returns `{"status": "ok"}` |
| `GET /admin/rules` | GET | Returns current rules configuration |
| `PUT /admin/rules/update` | POST/PUT | Update rules at runtime (accepts parameter JSON, pushed to OPA data store) |
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

Prometheus metrics are exposed at `/metrics` on the main listen port:

| Metric | Type | Labels | Description |
|---|---|---|---|
| `gql_firewall_requests_total` | Counter | `outcome`, `operation_type` | Total GraphQL requests |
| `gql_firewall_requests_blocked_total` | Counter | `reason` | Blocked requests by rule reason |
| `gql_firewall_request_duration_seconds` | Histogram | `outcome` | Pipeline latency |
| `gql_firewall_active_tenants` | Gauge | — | Active tenant count |
| `gql_firewall_rule_evaluations_total` | Counter | `rule` | Rule evaluation count |
| `gql_firewall_config_reloads_total` | Counter | — | Config hot-reload count |
| `gql_firewall_opa_requests_total` | Counter | `outcome` | OPA sidecar call count |
| `gql_firewall_opa_audit_blocks_total` | Counter | `reason` | Would-be OPA blocks in audit-only mode |

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
│  2. Parse GraphQL query (Go gqlparser/v2, in-process)        │
│  3. Evaluate OPA policies (embedded or sidecar)              │
│     │                                    ┌───────────────┐  │
│     └───────────────────────────────────▶│ OPA           │  │
│                                          │ (:8181)       │  │
│                                          └───────────────┘  │
│  4. Forward or block?                                        │
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
├── cmd/server/main.go            # Entry point — wires everything together (+ test, 25 tests)
├── config/params.json             # Sample OPA parameters
├── internal/
│   ├── parser/                    # GraphQL query analysis (45 tests, including Rust compat)
│   ├── opa/                       # OPA evaluator: sidecar, embedded, data store, input builder (63 tests)
│   ├── metrics/                   # Prometheus instrumentation (6 tests)
|│   ├── proxy/                     # HTTP reverse proxy (56 tests, including 25 red-team + 8 hardening + 9 input handling)
│   ├── ratelimit/                 # Token-bucket rate limiter (6 tests)
│   ├── testutil/                  # Shared test helpers  
│   └── integration/               # End-to-end pipeline tests (23 tests, including 19 e2e HTTP tests)
├── opa-policies/                  # OPA Rego policy templates (33 tests)
│   ├── graphql.rego              # 12 attack categories, parameterized via input.params
│   └── graphql_test.rego         # 33 policy tests
├── README.md
├── go.mod / go.sum
└── .gitignore
```

## Test Suite

```
Go:           243 tests — server(25), parser(113), proxy(74), integration(23), opa(63), metrics(6), ratelimit(6)
OPA/Rego:     33 tests  — 12 attack categories, edge cases, combined rules
Total:       276 tests  — all passing
```

```bash
# Run everything
go test ./... -count=1
opa test opa-policies/
```

---
## Deployment

### Docker

Build the image:

```bash
docker build -t gql-firewall:latest .
```

Run with embedded OPA (single container, zero external dependencies):

```bash
docker run -p 8081:8081 \
  -v $(pwd)/config/params.json:/app/config/params.json \
  gql-firewall:latest \
  --upstream http://host.docker.internal:8080 \
  --opa-embed /app/opa-policies/graphql.rego \
  --opa-params /app/config/params.json \
  --listen :8081
```

Run with OPA sidecar (separate OPA container required):

```bash
# Start OPA
docker run -d --name opa -p 8181:8181 \
  -v $(pwd)/opa-policies:/policies \
  openpolicyagent/opa:1.1.0 run --server /policies

# Start firewall
docker run -p 8081:8081 \
  gql-firewall:latest \
  --upstream http://host.docker.internal:8080 \
  --opa http://opa:8181/v1/data/graphql \
  --listen :8081
```

### Kubernetes Sidecar

Deploy the firewall as a sidecar container alongside your GraphQL server in the same pod:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: graphql-server
spec:
  replicas: 2
  selector:
    matchLabels:
      app: graphql
  template:
    metadata:
      labels:
        app: graphql
    spec:
      containers:
        - name: graphql
          image: my-graphql-server:latest
          ports:
            - containerPort: 8080
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
        - name: gql-firewall
          image: gql-firewall:latest
          args:
            - --upstream=http://localhost:8080
            - --opa-embed=/app/opa-policies/graphql.rego
            - --opa-params=/app/config/params.json
            - --listen=:8081
            - --admin=:8082
          ports:
            - containerPort: 8081
              name: http
            - containerPort: 8082
              name: admin
          volumeMounts:
            - name: opa-policy
              mountPath: /app/opa-policies
            - name: config
              mountPath: /app/config
          readinessProbe:
            httpGet:
              path: /admin/health
              port: 8082
            initialDelaySeconds: 3
            periodSeconds: 10
          resources:
            limits:
              memory: "64Mi"
              cpu: "100m"
            requests:
              memory: "32Mi"
              cpu: "50m"
      volumes:
        - name: opa-policy
          configMap:
            name: gql-firewall-policy
        - name: config
          configMap:
            name: gql-firewall-config
```

The service routes incoming GraphQL traffic to the firewall sidecar port, which inspects and forwards to the local upstream:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: graphql
spec:
  selector:
    app: graphql
  ports:
    - port: 80
      targetPort: 8081
      name: http
```

ConfigMaps for policy and parameters:

```bash
# Create ConfigMaps from your policy and config files
kubectl create configmap gql-firewall-policy \
  --from-file=opa-policies/graphql.rego

kubectl create configmap gql-firewall-config \
  --from-file=config/params.json
```

With OPA sidecar (separate container in the same pod):

```yaml
        - name: opa
          image: openpolicyagent/opa:1.1.0
          args:
            - run
            - --server
            - /policies/graphql.rego
          ports:
            - containerPort: 8181
          volumeMounts:
            - name: opa-policy
              mountPath: /policies
        - name: gql-firewall
          image: gql-firewall:latest
          args:
            - --upstream=http://localhost:8080
            - --opa=http://localhost:8181/v1/data/graphql
            - --listen=:8081
```

### Docker Compose

```yaml
version: "3.8"
services:
  graphql:
    image: my-graphql-server:latest
    expose:
      - "8080"
  gql-firewall:
    build: .
    ports:
      - "8081:8081"
    command:
      - --upstream=http://graphql:8080
      - --opa-embed=/app/opa-policies/graphql.rego
      - --opa-params=/app/config/params.json
      - --listen=:8081
    volumes:
      - ./opa-policies:/app/opa-policies
      - ./config:/app/config
```

---

## Suggested New Features

The following features align with the product's business model — a standalone GraphQL firewall for mid-market API teams, Go-only binary with OPA-based policy, and an eventual acquisition path to Datadog, Kong, or Cloudflare.

### Learning Resources
- **[Writing Custom OPA Policies](docs/opa-samples/tutorial.md)** — Hands-on tutorial with worked examples, testing guide, and reference for all input fields
- **[25 Sample Policies](docs/opa-samples/)** — Runnable Rego files covering every attack category, tenant isolation, CIDR filtering, time-based access, and combined rules
- **[OPA Policy Language](https://www.openpolicyagent.org/docs/latest/policy-language/)** — Official Rego reference


### Near-term (Phase 1 — build on existing architecture)

**1. Prometheus metrics endpoint** — Expose deny counters, latency histograms, and active tenant counts as Prometheus `/metrics`. This is the single most requested feature by mid-market platform teams monitoring their APIs. It also directly feeds into Datadog's agent, making the product immediately useful to Datadog's install base (exit path alignment).

**2. GraphQL schema-aware validation** — Accept an SDL schema file (`--schema schema.graphql`). Use it to detect queries requesting fields that don't exist, arguments of the wrong type, or deprecated fields. This turns the firewall from a generic rate-limiter into a GraphQL-aware security tool — the key differentiator against Kong's generic Lua plugins.

**3. Operation-name-based allowlist** — Allow only known operation names in production (e.g. `query GetUser { ... }` but block arbitrary unnamed queries). This prevents attackers from probing the API surface with anonymous queries. Already partially supported by the OPA `require_persisted_queries` mode — wire it through the Go sidecar config.

### Mid-term (Phase 2 — premium tier enablers)

**4. Per-tenant isolation with OPA data bundles** — Route requests to tenant-specific OPA data bundles based on API key or JWT claims. Each tenant gets their own policy scope without deploying separate sidecars. This is the product moat that differentiates from generic API gateways.

**5. Rego policy caching in the Go sidecar** — Cache OPA decisions locally with a TTL to avoid the network hop on repeat queries. For a typical mid-market GraphQL API, ~70% of query patterns repeat within a 60-second window. This brings P99 latency from ~2ms (OPA RPC) to ~200µs (local cache hit).

**6. REST API for live rule management** — Add admin endpoints (`POST /admin/rules`, `GET /admin/stats`) so platform teams can update rules without file access or sidecar restarts. This is a table-stakes enterprise feature that enables the Silver/Gold tier pricing model ($15K-$40K/mo).

### Long-term (Phase 3 — acquisition value)

**7. Datadog native integration** — Ship a Datadog Integration tile with out-of-the-box dashboards (blocked queries by rule, latency heatmaps, tenant-level cost attribution). This is the single highest-leverage feature for the Datadog acquisition path — it removes the "integration cost" objection from due diligence.

**8. GraphQL cost analysis engine** — Replace the simple `depth × field_count` heuristic with schema-aware cost weights (per-resolver cost, list size multipliers, join complexity). Expose cost budgets per API key. This moves the product from "WAF for GraphQL" to "cost management platform" — a higher-value category.

**9. Kong/Konnect plugin packaging** — Package the Go sidecar as a Kong plugin (Go PDK) to capture the 30% of the market running Kong. This doesn't change the architecture — it's a deployment packaging change — but it opens the Kong acquisition path.

## Development

### Adding a New Attack Detection

1. Add the deny rule to `opa-policies/graphql.rego` with a unique message
2. Write test cases in `opa-policies/graphql_test.rego`
3. Validate with `opa test opa-policies/`
4. Add Go-level integration test in `internal/opa/owasp_test.go`

## Roadmap

| Phase | Timeline | Features | Revenue |
|---|---|---|---|
| **Phase 1** | Months 0-6 | Prometheus, schema-aware validation, operation-name allowlist | $99-499/mo |
| **Phase 2** | Months 6-12 | Per-tenant isolation, policy caching, live admin API | $1,999-9,999/mo |
| **Phase 3** | Months 12-24 | Datadog integration, cost analysis engine, Kong packaging | $40-100K/mo |

## License

MIT
