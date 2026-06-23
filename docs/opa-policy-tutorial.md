# Writing Custom OPA Policies for gql-firewall

A hands-on guide to creating, testing, and deploying Rego policies for the
GraphQL firewall. You should have some familiarity with OPA concepts (rules,
rules, the `input` document, and `opa test`). If not, start with the official
[OPA Policy Language
documentation](https://www.openpolicyagent.org/docs/latest/policy-language/)
first — this tutorial builds on it.

## Table of Contents

1. [How the firewall integrates with OPA](#1-how-the-firewall-integrates-with-opa)
2. [The Input document — what data your policy sees](#2-the-input-document--what-data-your-policy-sees)
3. [Policy anatomy — deny-override model](#3-policy-anatomy--deny-override-model)
4. [Parameterisation — separating config from code](#4-parameterisation--separating-config-from-code)
5. [Writing custom policies — worked examples](#5-writing-custom-policies--worked-examples)
6. [Testing policies with `opa test`](#6-testing-policies-with-opa-test)
7. [Deploying custom policies](#7-deploying-custom-policies)
8. [Reference — all input fields](#8-reference--all-input-fields)
9. [Further reading](#9-further-reading)

---

## 1. How the firewall integrates with OPA

The gql-firewall sidecar parses every incoming GraphQL request and builds a
structured `input` document. It sends this document to OPA for evaluation,
either:

- **Embedded mode** (`--opa-embed policies.rego`): in-process Rego evaluation
  using the OPA Go library (~10µs per decision). No external dependencies.
- **Sidecar mode** (`--opa http://localhost:8181/v1/data/graphql`): evaluates
  policies via a remote OPA HTTP endpoint. Used for scale-out deployments
  where you want OPA's decision caching and live policy updates.

In both modes, the policy package MUST be `graphql` and the decision path
MUST be `data.graphql.allow` / `data.graphql.deny`. The firewall calls
`data.graphql.allow` to determine if a request passes, and falls back to
`data.graphql.deny` to extract the block reason.

```
     ┌──────────┐      GraphQL query       ┌──────────────┐
     │  Client   │ ───────────────────────► │  gql-firewall │
     └──────────┘                           │  sidecar      │
          ▲                                 └──────┬───────┘
          │                                        │ parse & build input
          │                                        ▼
          │                                 ┌──────────────┐
          │                                 │  OPA Engine   │
          │                                 │  (embedded or │
          │                                 │   sidecar)    │
          │                                 └──────┬───────┘
          │                                        │
          │                allowed / blocked + reason
          │◄───────────────────────────────────────┘
```

---

## 2. The Input document — what data your policy sees

Every policy receives an `input` document with the following structure.
Your Rego rules reference these fields as `input.field_name`.

```json
{
  "operation_type":     "query|mutation|subscription",
  "operation_name":     "GetUser",             // or "" if anonymous
  "depth":              3,                     // max nesting depth
  "field_count":        12,                    // total fields requested
  "field_paths":        ["user", "user.name", "user.email", "posts", "posts.title"],
  "tenant_id":          "acmecorp",            // from X-API-Key header, or ""
  "directives":         2,                     // total @directives used
  "batch_size":         1,                     // operations in this request
  "argument_depth":     2,                     // max argument nesting
  "lists_requested":    1,                     // plural-field heuristic count
  "fragment_spread_count": 0,                  // ... on Type / fragment spreads
  "query_hash":         "a1b2c3d4",            // first 8 bytes of SHA-256
  "params":             { /* your configuration — see below */ },
  "tenant_config":      { /* tenant-specific overrides — see below */ }
}
```

> **Why `input.params` and not hardcoded values?** Separating configuration
> from policy code means you can change limits (e.g., `depth_limit`) via
> the admin API without editing Rego files. The sidecar populates
> `input.params` from either a JSON file (`--opa-params`) or the in-memory
> data store (updated via `POST /admin/rules/update`).

---

## 3. Policy anatomy — deny-override model

Every gql-firewall policy follows the same structure:

```rego
package graphql

# By default, deny everything that isn't explicitly allowed.
default allow := false

# Allow if no deny rules match.
allow if {
    count(deny) == 0
}

# Deny rules — add your checks here.
# deny contains "reason message" if { ... condition ... }
```

**Key rules of the deny-override model:**

1. **`default allow := false`** — requests are blocked unless an allow
   rule says otherwise. This is the safe default: a bug in your policy
   blocks traffic rather than allowing malicious queries through.

2. **`allow if { count(deny) == 0 }`** — the only allow rule. It fires
   when the `deny` set is empty. If any deny rule matches, `allow` stays
   `false`.

3. **`deny contains <reason> if { ... }`** — each deny rule adds a message
   to the `deny` set. The firewall takes the first message from the set
   and returns it as the `"reason"` field in the 403 response.

4. **All or nothing** — you cannot `allow` some fields and `deny` others
   in the same request. If the query contains ANY blocked field, the
   entire request is rejected. This is intentional: GraphQL queries are
   atomic operations.

> **Why `count(deny) == 0` instead of `not deny`?**
>
> In Rego v1 (which gql-firewall uses), `deny` is a **set**. Writing
> `not deny` checks whether the expression `deny` produces any bindings.
> Since `deny` always produces a value (even if empty), `not deny` would
> always be false. The correct pattern is `count(deny) == 0`, which checks
> that the set has zero elements.
>
> See [OPA v1 migration
> guide](https://www.openpolicyagent.org/docs/latest/v1-compatibility/) for
> details on v1 syntax changes.

---

## 4. Parameterisation — separating config from code

Hardcoding values in Rego makes every limit change require a policy file
edit and firewall restart. Instead, use `input.params.*`:

```rego
# ❌ Bad: hardcoded limit
deny contains msg if {
    input.depth > 10
    msg := "too deep"
}

# ✅ Good: parameterised limit
deny contains msg if {
    input.depth > input.params.depth_limit
    msg := sprintf("depth %d exceeds limit %v", [input.depth, input.params.depth_limit])
}
```

### Setting parameters

**Via JSON file** (at startup):

```json
{
  "depth_limit": 10,
  "max_field_count": 100,
  "blocked_operations": ["subscription"],
  "field_blocklist": ["__schema", "user.ssn", "user.password"]
}
```

```bash
gql-firewall --opa-embed policies.rego --opa-params config/params.json --upstream :8080
```

**Via admin API** (at runtime — no restart):

```bash
curl -X POST http://localhost:8082/admin/rules/update \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer my-token" \
  -d '{"depth_limit": 5, "max_field_count": 50}'
```

### Tenant-specific overrides

When a request has an `X-API-Key` header, the firewall extracts a tenant ID
(everything before the last `_`) and populates `input.tenant_config` with
that tenant's configuration:

```bash
curl -X PUT http://localhost:8082/admin/tenants/acmecorp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer my-token" \
  -d '{"depth_limit": 3}'
```

Your policy can check tenant overrides:

```rego
deny contains msg if {
    input.tenant_config
    input.tenant_config.depth_limit
    input.depth > input.tenant_config.depth_limit
    msg := sprintf("tenant depth limit exceeded", [])
}
```

Note the **guarding pattern**: `input.tenant_config` checks that the value
exists before accessing its fields. Without this guard, accessing
`input.tenant_config.depth_limit` on a request without a tenant ID would
cause a Rego evaluation error.

---

## 5. Writing custom policies — worked examples

### Example 1: Block anonymous queries

Some environments require every query to have a named operation (e.g.,
`query GetUser { ... }`). Anonymous queries like `{ user { name } }` are
harder to log, audit, and allowlist.

```rego
deny contains "anonymous queries are not allowed" if {
    input.operation_name == ""
    not input.params.allow_anonymous
}
```

**How it works:**

| Condition | Behaviour |
|---|---|
| `input.operation_name == ""` | True when the query has no name |
| `not input.params.allow_anonymous` | Only blocks if the parameter is NOT set to true |
| Combined | Blocks anon queries by default; allows via `"allow_anonymous": true` |

**Test:**
```rego
test_anonymous_query_blocked if {
    some msg in deny with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["hello"], "operation_name": "",
        "params": {}
    }
    msg == "anonymous queries are not allowed"
}

test_named_query_allowed if {
    allow with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["hello"], "operation_name": "GetHello",
        "params": {}
    }
}
```

### Example 2: Block by source IP (standalone proxy mode)

When running as a standalone proxy (not sidecar), `input.source_ip` can be
populated from `r.RemoteAddr`. This policy blocks requests from specific
IPs or CIDR ranges.

```rego
deny contains msg if {
    input.source_ip
    net.cidr_contains(input.params.blocked_cidrs[_], input.source_ip)
    msg := sprintf("requests from %q are blocked", [input.source_ip])
}
```

**Parameters:**
```json
{
  "blocked_cidrs": ["10.0.0.0/8", "192.168.0.0/16"]
}
```

**How it works:**
- `input.source_ip` — guards against nil/empty (skips the rule if unset)
- `net.cidr_contains(cidr, ip)` — built-in Rego function for CIDR matching
- `input.params.blocked_cidrs[_]` — iterates over the array, matching any entry

> **Note:** In sidecar mode (K8s), `r.RemoteAddr` is the pod IP of the
> previous hop (kube-proxy or sidecar proxy), not the original client.
> `X-Forwarded-For` is the correct source in that deployment. See
> [IP filtering](#) in the deployment guide for details.

### Example 3: Rate-limit mutations by operation name

Rate limiting at the application layer complements the token-bucket rate
limiter (`--rate-limit`). This policy enforces a stricter limit on specific
expensive mutations.

```rego
deny contains msg if {
    input.operation_type == "mutation"
    input.operation_name == input.params.expensive_mutations[_]
    msg := sprintf("mutation %q is rate limited", [input.operation_name])
}
```

**Parameters:**
```json
{
  "expensive_mutations": ["bulkImport", "generateReport", "sendEmailBatch"]
}
```

**Analysis:** This is a **permit list** pattern — it names the specific
mutations to block, not the ones to allow. If you add a new expensive
mutation later, you add it to `expensive_mutations` in the params JSON.
Everything else (including new mutations you forgot about) passes through
automatically. Use this pattern when you want to surgically block known-cost
operations without inadvertently blocking new ones.

For the inverse (allow only specific mutations), use the
`allowed_operations` parameter instead.

### Example 4: Rate-limit by query hash

Persisted queries have known SHA-256 hashes. You can enforce per-hash rate
limits to prevent a compromised persisted query from being abused.

```rego
deny contains msg if {
    input.query_hash == "a1b2c3d4"
    msg := "this persisted query version is deprecated — update your client"
}
```

**Analysis:** This is a **hard block** on a specific query version. The
hash `a1b2c3d4` matches the first 8 bytes of the full SHA-256 of the query
string. When you deprecate a query version in your client, you add its hash
to the blocklist. Clients that don't update receive a clear error message
telling them what to do.

### Example 5: Require specific fields to be requested together

Some GraphQL servers require `id` to be requested alongside any field for
caching/join purposes. This policy checks that `id` is present whenever
certain sensitive fields are requested.

```rego
deny contains msg if {
    some sensitive in input.params.sensitive_fields
    some path in input.field_paths
    endswith(path, sensitive)
    not field_in_paths("id")
    msg := sprintf("field %q requires 'id' to be requested", [sensitive])
}

field_in_paths(target) if {
    some path in input.field_paths
    endswith(path, target)
}
```

**Parameters:**
```json
{
  "sensitive_fields": ["ssn", "creditCard", "password"]
}
```

**Analysis:** This uses `endswith` instead of exact match so that
`user.ssn`, `admin.ssn`, and `ssn` all match the sensitive field check.
This is deliberate — you don't want an attacker to bypass the rule by
requesting `admin { ssn }` instead of just `ssn`. The `endswith` pattern
catches field access at any nesting depth.

### Example 6: Combined rule — block deep mutations

A common attack pattern: expensive mutations with deep nesting. This rule
combines two dimensions.

```rego
deny contains msg if {
    input.operation_type == "mutation"
    input.depth > input.params.mutation_depth_limit
    msg := sprintf("mutation depth %d exceeds limit %v", [input.depth, input.params.mutation_depth_limit])
}
```

**Parameters:**
```json
{
  "mutation_depth_limit": 3
}
```

**Analysis:** This is an **intersection rule**: it only fires when BOTH
conditions are true. Queries at depth 10 pass freely; mutations at depth
3 are blocked. This is possible because the firewall evaluates the same
policy for every request — the distinction comes from checking
`input.operation_type`. You can build arbitrarily specific intersections
this way: "block fragment-heavy subscriptions" or "block batched queries
from external tenants."

### Example 7: Tenant-specific field blocklist

Tenant configurations (`input.tenant_config`) can carry their own
blocklists that override the global `field_blocklist`. This is useful when
a specific customer contract forbids certain data fields.

```rego
deny contains msg if {
    input.tenant_config
    input.tenant_config.field_blocklist
    some blocked in input.tenant_config.field_blocklist
    some path in input.field_paths
    path == blocked
    msg := sprintf("field %q is blocked by your organisation's policy", [path])
}
```

**Admin API usage:**
```bash
curl -X PUT http://localhost:8082/admin/tenants/bankingcorp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer my-token" \
  -d '{"field_blocklist": ["account.balance", "account.transactions"]}'
```

---

## 6. Testing policies with `opa test`

OPA has a built-in test framework. Test files sit alongside your policy
files and use the `with input as` construct to provide test data.

### Basic test structure

```rego
package graphql

test_my_rule_name if {
    # Assert: deny set contains "my reason"
    some msg in deny with input as {
        "depth": 1, "field_count": 1, "operation_type": "query",
        "field_paths": ["hello"],
        "params": {"depth_limit": 10}
    }
    msg == "my reason"
}
```

### Testing allowed queries

```rego
test_allowed_if_safe if {
    # Assert: allow is true with this input
    allow with input as {
        "depth": 5, "field_count": 3, "operation_type": "query",
        "field_paths": ["user", "user.name"],
        "params": {"depth_limit": 10}
    }
}
```

### Testing tenant-specific rules

```rego
test_tenant_depth_blocked if {
    some msg in deny with input as {
        "depth": 7, "field_count": 3, "operation_type": "query",
        "field_paths": ["report"],
        "tenant_id": "strictenant",
        "params": {"depth_limit": 10},
        "tenant_config": {"depth_limit": 5}
    }
    msg == "tenant depth limit exceeded"
}
```

### Running tests

```bash
# Run all tests in your policy directory
opa test opa-policies/ -v

# Run a specific test
opa test opa-policies/ -v -r 'test_depth_'

# See coverage
opa test opa-policies/ --coverage
```

### Test pattern reference

The gql-firewall built-in policies have 33 tests that cover every attack
category. Look at `opa-policies/graphql_test.rego` for real-world examples
including:
- Tests that check for specific deny message substrings
- Tests with empty params (default behaviour)
- Tests for nested field paths (`user.__typename`)
- Tests for fragment spread counting
- Tests for tenant overrides
- A `test_no_extra_denies` rule that verifies no unexpected rules fire

---

## 7. Deploying custom policies

### Embedded mode (single binary, no OPA sidecar)

```bash
gql-firewall \
  --upstream http://localhost:8080 \
  --opa-embed /etc/gql-firewall/policies/custom.rego \
  --opa-params /etc/gql-firewall/config/params.json
```

### Sidecar mode (shared OPA instance)

1. **Load your policy into OPA:**
```bash
curl -X PUT http://localhost:8181/v1/policies/graphql \
  --data-binary @custom.rego
```

2. **Start the firewall pointing at OPA:**
```bash
gql-firewall \
  --upstream http://localhost:8080 \
  --opa http://localhost:8181/v1/data/graphql
```

### Kubernetes with ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: gql-firewall-policy
data:
  custom.rego: |
    package graphql
    default allow := false
    allow if { count(deny) == 0 }
    deny contains msg if {
      input.depth > input.params.depth_limit
      msg := sprintf("depth %d exceeds limit", [input.depth])
    }
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: gql-firewall
          volumeMounts:
            - name: policy
              mountPath: /etc/gql-firewall/policies
      volumes:
        - name: policy
          configMap:
            name: gql-firewall-policy
```

---

## 8. Reference — all input fields

| Field | Type | Description | Populated by |
|---|---|---|---|
| `operation_type` | string | `"query"`, `"mutation"`, or `"subscription"` | Parser |
| `operation_name` | string | Named operation (e.g. `"GetUser"`) or `""` if anonymous | Parser |
| `depth` | number | Maximum field nesting depth | Parser |
| `field_count` | number | Total fields requested (including aliases) | Parser |
| `field_paths` | array[string] | Dot-separated paths of all requested fields | Parser |
| `tenant_id` | string | Tenant ID from `X-API-Key` header, or `""` | Proxy handler |
| `directives` | number | Total `@directive` usages across all fields | Parser |
| `batch_size` | number | Number of operations in the request | Parser |
| `argument_depth` | number | Maximum nesting depth of argument values | Parser |
| `lists_requested` | number | Fields with plural names (heuristic) | Parser |
| `fragment_spread_count` | number | Total `... on Type` and `...FragmentName` usages | Parser |
| `query_hash` | string | First 8 bytes of SHA-256 as hex string | Parser |
| `params` | object | Configuration parameters (see below) | Go data store |
| `tenant_config` | object/null | Per-tenant overrides, or `null` if unauthenticated | Go data store |

### Common parameter fields

These are the built-in parameters recognised by the default policy. Your
custom policy can use any keys you define.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `depth_limit` | number | 10 | Max query nesting depth |
| `max_field_count` | number | 100 | Max fields (alias bomb protection) |
| `max_directives` | number | 5 | Max `@directive` usages |
| `max_batch_size` | number | 1 | Max operations per request |
| `field_blocklist` | array[string] | — | Blocked dot-separated field paths |
| `field_allowlist` | array[string] | — | If set, ONLY these paths are allowed |
| `blocked_operations` | array[string] | — | Blocked operation types |
| `allowed_operations` | array[string] | — | If set, ONLY these types are allowed |
| `max_argument_depth` | number | 5 | Max argument value nesting |
| `max_lists_requested` | number | 5 | Max plural fields |
| `max_fragment_spreads` | number | 15 | Max fragment spread usages |
| `cost_budget` | number | 50 | Max `depth * field_count` |
| `require_persisted_queries` | boolean | false | Block dynamic (non-hashed) queries |

---

## 9. Further reading

### OPA fundamentals

- [OPA Policy Language (Rego) documentation](https://www.openpolicyagent.org/docs/latest/policy-language/)
  — official Rego reference. Covers syntax, rules, comprehensions, and built-in
  functions.
- [OPA Policy Testing](https://www.openpolicyagent.org/docs/latest/policy-testing/)
  — how to write `opa test` rules, run them, and generate coverage reports.
- [OPA v1 compatibility guide](https://www.openpolicyagent.org/docs/latest/v1-compatibility/)
  — differences between Rego v0 and v1 syntax. gql-firewall uses v1.
- [OPA REST API](https://www.openpolicyagent.org/docs/latest/rest-api/)
  — API reference for pushing policies and data to an OPA sidecar.
- [OPA built-in functions](https://www.openpolicyagent.org/docs/latest/policy-reference/#built-in-functions)
  — reference for all built-in functions including `net.cidr_contains`,
  `sprintf`, `startswith`, `endswith`, `count`, and `walk`.

### GraphQL security

- [OWASP GraphQL Top 10](https://github.com/OWASP/API-Security/blob/master/2023/en/src/OWASP-API-Security-Top-10.md)
  — the attack taxonomy that gql-firewall's built-in policies are based on.
- [GraphQL security best practices](https://graphql.org/learn/security/)
  — official GraphQL Foundation guidance on depth limiting, cost analysis,
  and persisted queries.

### gql-firewall specifics

- `opa-policies/graphql.rego` — the built-in production policy with all 12
  attack categories. Read this file to understand the full deny rule set.
- `opa-policies/graphql_test.rego` — 33 test cases covering every rule,
  including edge cases and tenant overrides. Use this as a template for your
  own test files.
- `config/params.json` — sample parameters file. Copy this as a starting
  point for your own configuration.

### Rego patterns

- [Rego by Example](https://www.openpolicyagent.org/docs/latest/#rego-by-example)
  — interactive tutorials on the OPA website.
- [The Rego Playground](https://play.openpolicyagent.org/)
  — online editor for testing Rego policies in the browser without installing
  anything.
- [OPA Ecosystem](https://www.openpolicyagent.org/ecosystem/)
  — community integrations and example policies for various platforms
  (Kubernetes, Terraform, Istio, Envoy).

---

## Quick reference card

```rego
package graphql

# Default: safe (block if anything goes wrong)
default allow := false

# Allow only when no deny rules fire
allow if { count(deny) == 0 }

# ── Guard pattern: check a field exists before accessing sub-fields ──
deny contains msg if {
    input.params.my_param                    # guard
    input.depth > input.params.my_param      # actual condition
    msg := "my_param exceeded"
}

# ── Contains rule: adds a string to the deny set ──
deny contains "always blocked" if {
    false  # example — replace with real condition
}

# ── Iteration over arrays ──
deny contains msg if {
    some item in input.params.my_list
    input.operation_name == item
    msg := sprintf("operation %q is blocked", [item])
}

# ── Field path matching ──
deny contains msg if {
    some blocked in input.params.field_blocklist
    some path in input.field_paths
    endswith(path, blocked)
    msg := sprintf("field %q is blocked", [path])
}

# ── Compound check (AND) ──
deny contains msg if {
    input.operation_type == "mutation"
    input.depth > input.params.mutation_depth_limit
    msg := "mutation too deep"
}

# ── Tenant override ──
deny contains msg if {
    input.tenant_config
    input.tenant_config.depth_limit
    input.depth > input.tenant_config.depth_limit
    msg := "tenant depth limit exceeded"
}
```
