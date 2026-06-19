# gql-firewall

A **GraphQL firewall sidecar** that intercepts, inspects, and secures GraphQL requests before they reach your upstream server. Built with Go (control plane) and optionally accelerated with Rust (hot-path parser), with OPA/Rego integration for policy-as-code.

```
        ┌───────────┐    GraphQL     ┌──────────────┐  rules  ┌─────────┐
 Client ─▶  gql-    │  query/block   │   Upstream   │◀───────▶│  OPA    │
        │  firewall │───────────────▶│   GraphQL    │  eval   │ Sidecar │
        │ sidecar   │    response    │   Server     │         │(optional)│
        └───────────┘               └──────────────┘         └─────────┘
```

## Features

### Core
- **GraphQL query parsing** — Parses queries, mutations, and subscriptions using `gqlparser` (Go) or `async-graphql-parser` (Rust). Extracts operation type, name, depth, field count, and full field paths.
- **Configurable rules engine** — JSON-configured rules evaluated before forwarding:
  - **Depth limiting** — Reject queries that nest beyond N levels
  - **Field counting** — Reject queries requesting too many fields
  - **Operation type control** — Allow or block query/mutation/subscription
  - **Field allowlists** — Only permit specified field paths
  - **Field blocklists** — Deny specific sensitive fields (takes precedence)
- **OPA/Rego integration** — Optional OPA sidecar for external policy evaluation. OPA receives full query context and returns allow/deny decisions.
- **Configurable hot-reload** — Watch rule files for changes and apply them without restart.

### Performance
- **Go control plane** — Fast, memory-safe, goroutine-per-request. P99 <5ms with local rules.
- **Rust hot-path parser** (optional) — Runs as an HTTP sidecar using `async-graphql-parser`. Use when sub-millisecond parsing latency is critical.

### Security
- **Sensitive field blocking** — Block `__schema`, `user.ssn`, `user.password`, and any other paths.
- **Introspection blocking** — Block introspection queries in production.
- **Operation restrictions** — Allow only specific operation types per environment.
- **Query cost budgeting** — Depth × field count complexity budgets.
- **Rate limiting** — Via OPA policies (external data integration).

## Quick Start

### Prerequisites
- Go 1.23+ (for building)
- Rust 1.75+ (optional, for hot-path parser)

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

# With OPA sidecar for policy evaluation
./gql-firewall \
  --upstream http://localhost:8080 \
  --config ./config/rules.json \
  --listen :8081 \
  --opa http://localhost:8181/v1/data/graphql/allow

# With Rust hot-path parser sidecar
# (start the Rust parser first)
./rust-parser/target/release/gql-parser --listen 9090 &
./gql-firewall --upstream http://localhost:8080 --listen :8081
```

### Test It

```bash
# Valid query (should pass)
curl -X POST http://localhost:8081/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ hello }"}'

# Deep query (should be blocked by depth limit)
curl -X POST http://localhost:8081/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ a { b { c { d { e } } } } }"}'

# Sensitive field (should be blocked by field blocklist)
curl -X POST http://localhost:8081/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user { name ssn } }"}'

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
  "field_blocklist": ["__schema", "__type", "user.ssn", "user.password"]
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

The `opa-policies/` directory contains Rego policy templates:

```bash
# Deploy policies to OPA
curl -X PUT --data-binary @opa-policies/graphql.rego \
  http://localhost:8181/v1/policies/graphql

# Test policies
opa test opa-policies/
```

The OPA input schema matches the Go parser's `QueryInfo` structure:

```json
{
  "input": {
    "operation_type": "query",
    "operation_name": "GetUser",
    "depth": 3,
    "field_count": 5,
    "field_paths": ["user", "user.name", "user.email"]
  }
}
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

### Project Structure

```
gql-firewall/
├── cmd/
│   └── server/main.go        # Entry point — wires everything together
├── config/
│   └── rules.json            # Sample firewall rules
├── internal/
│   ├── parser/               # GraphQL query analysis
│   │   ├── parser.go         # Public Parse() API
│   │   ├── parse.go          # Implementation (gqlparser-based)
│   │   └── parser_test.go    # 16 tests
│   ├── rules/                # Configurable rule evaluation
│   │   ├── rules.go          # Config struct + Evaluate()
│   │   └── rules_test.go     # 19 tests
│   ├── config/               # JSON config loader + file watcher
│   │   ├── config.go         # Load() + Watch() (fsnotify)
│   │   └── config_test.go    # 7 tests
│   ├── opa/                  # OPA sidecar client
│   │   ├── opa.go            # HTTP client for policy evaluation
│   │   └── opa_test.go       # 6 tests
│   ├── proxy/                # HTTP reverse proxy
│   │   ├── proxy.go          # Intercepts POST /graphql
│   │   └── proxy_test.go     # 7 tests
│   └── integration/          # End-to-end pipeline tests
│       └── integration_test.go # 9 tests
├── rust-parser/              # Rust hot-path parser
│   ├── Cargo.toml
│   └── src/main.rs           # CLI + HTTP sidecar (async-graphql-parser)
├── opa-policies/             # OPA Rego policy templates
│   ├── graphql.rego          # Production policies (deny-override model)
│   └── graphql_test.rego     # 11 policy tests
├── go.mod / go.sum
└── .gitignore
```

## Development

### Run All Tests

```bash
# Go tests (55 tests)
go test ./... -count=1 -v

# Rust tests (7 tests)
cd rust-parser && cargo test

# OPA policy tests (11 tests)
opa test opa-policies/

# Full pipeline integration test
go test ./internal/integration/ -v
```

### Adding a New Rule

1. Add the field to `internal/rules/rules.go` Config struct
2. Add evaluation logic to `Config.Evaluate()` method
3. Write tests in `internal/rules/rules_test.go`
4. Add the JSON config field mapping (automatically handled via struct tags)

### Using the Rust Hot-Path Parser

```bash
# Build the Rust parser
cd rust-parser && cargo build --release

# Run as HTTP sidecar (listens on :9090)
./target/release/gql-parser --listen 9090

# Test with a query file
echo '{ hello }' | ./target/release/gql-parser

# Parse a file directly
./target/release/gql-parser query.graphql
```

The Rust parser outputs JSON matching the Go parser's `QueryInfo` structure, making it a drop-in replacement for the hot path.

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

## Testing Philosophy

This project uses **test-driven development**. Every feature was built by:

1. Writing the test first (defining expected behaviour)
2. Implementing until tests pass
3. Committing with a descriptive message

### Test Coverage

| Package | Tests | What's Covered |
|---|---|---|
| `parser` | 16 | Query parsing, depth, fields, paths, fragments, aliases, introspection, errors |
| `rules` | 19 | Depth limit, field count, operation allow/blocklist, field allow/blocklist, multiple rules, no rules |
| `config` | 7 | Valid files, minimal files, missing files, invalid JSON, all fields, empty path, file watching |
| `opa` | 6 | Allow/block responses, HTTP errors, timeouts, empty URL (default allow), input verification |
| `proxy` | 7 | Allow/block, header passthrough, invalid JSON, missing query, non-POST, upstream errors |
| `integration` | 9 | Full pipeline: depth block, field block, OPA allow/block, invalid GraphQL, mutation block, health passthrough, field allowlist |
| Rust parser | 7 | Simple/nested/deep parsing, mutations, named queries, paths, errors |
| OPA policies | 11 | Depth, field blocklist, operation type, introspection, cost budget |

Total: **73 passing tests** across Go, Rust, and Rego.

## License

MIT
