# gql-firewall OPA Policy Samples

This directory contains 25 fully-documented sample Rego policies that
demonstrate common GraphQL firewall use cases. Each file is a complete,
runnable policy with embedded test cases.

## How to use

```bash
# Test individual samples (they all share "package graphql")
opa test docs/opa-samples/01-deny-override-structure.rego -v
opa test docs/opa-samples/05-depth-limit.rego -v

# Test a specific sample with coverage
opa test docs/opa-samples/07-introspection-blocking.rego --coverage

# Test all samples at once (expects errors due to conflicting defaults)
# Instead, run them individually or in small groups
for f in docs/opa-samples/0[1-9]*.rego; do
  echo "=== $(basename $f) ==="
  opa test "$f" -v
done
```

## Index

| # | File | Topic | OWASP |
|---|---|---|---|
| 01 | `deny-override-structure.rego` | The deny-override pattern explained | — |
| 02 | `input-document-assertions.rego` | Understanding what input looks like | — |
| 03 | `parameterisation.rego` | Params vs hardcoded values | — |
| 04 | `testing-patterns.rego` | How to write and run tests | — |
| 05 | `depth-limit.rego` | Maximum query nesting depth | API4 |
| 06 | `field-count-limit.rego` | Alias bomb / field duplication | API4 |
| 07 | `introspection-blocking.rego` | Block __schema, __type, __typename | API8 |
| 08 | `directive-limit.rego` | Limit @directive usage | — |
| 09 | `batch-size-limit.rego` | Block multi-operation requests | — |
| 10 | `field-blocklist.rego` | Block sensitive fields (PII) | API3 |
| 11 | `field-allowlist.rego` | Only allow specific fields | API3 |
| 12 | `operation-type-control.rego` | Block/allowed operations | — |
| 13 | `argument-depth-limiter.rego` | Max argument nesting | — |
| 14 | `list-field-limiter.rego` | N+1 abuse prevention | — |
| 15 | `fragment-spread-limiter.rego` | Fragment explosion protection | — |
| 16 | `query-cost-budget.rego` | Complexity budget (depth×count) | API4 |
| 17 | `persisted-query-enforcement.rego` | Block dynamic queries | — |
| 18 | `anonymous-query-blocking.rego` | Require named operations | — |
| 19 | `tenant-isolation.rego` | Per-tenant policy overrides | — |
| 20 | `source-ip-filtering.rego` | CIDR-based access control | — |
| 21 | `time-based-access.rego` | Time-of-day restrictions | — |
| 22 | `deprecate-query-hash.rego` | Block deprecated query versions | — |
| 23 | `combined-deep-mutations.rego` | Intersection: mutation + depth | API4 |
| 24 | `combined-expensive-auth.rego` | Intersection: field + tenant | API3 |
| 25 | `require-pagination.rego` | Force pagination on list fields | — |

## Further reading

See the [tutorial](tutorial.md) for a detailed walkthrough of policy
anatomy, parameterisation, and testing.

See [OPA Playground](https://play.openpolicyagent.org/) to experiment
with Rego in the browser.
