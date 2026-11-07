# Tenant identity: trust model and operations

A tenant ID selects which policy configuration (`tenant_config`) applies, so
the firewall is explicit about whether that identity is **proven** or merely
**asserted**. This document covers the modes, key issuance and rotation, and the
three-stage migration from header mode to verified keys.

## Modes

| `--tenant-mode` | Identity source | Trust | Notes |
|---|---|---|---|
| `header` (default) | `X-API-Key` prefix | Asserted, not verified | Only for deployments behind a trusted gateway that authenticates the caller and strips inbound `X-API-Key` |
| `hmac` | Signed key, verified against `--tenant-key-secret` | Verified | Key format below; expired or forged keys get `401` |
| `jwt`, `mtls` | — | — | Not implemented; requesting them fails at startup |

Whichever mode is active, the OPA input carries `tenant_identity_source`
(`header` / `hmac` / `none`) and `tenant_known`, so policy can refuse asserted
identities today:

```rego
deny contains msg if {
    input.params.require_verified_tenant == true
    input.tenant_id != ""
    input.tenant_identity_source != "hmac"
    msg := sprintf("tenant identity source %q is unverified", [input.tenant_identity_source])
}
```

## Key format

```
v1.<base64url(payload)>.<base64url(HMAC-SHA256(secret, "v1." + payload))>
```

`payload` is `{"tid":"acme","exp":1730000000,"iat":1729996400}`. `exp` is Unix
seconds and is omitted for non-expiring keys. Properties:

- The MAC covers the version prefix, so a future `v2` cannot be downgraded to
  `v1`.
- Verification happens **before** the payload is decoded, so no attacker JSON is
  parsed for an unauthenticated caller.
- MAC comparison uses `hmac.Equal` (constant time) and every configured secret
  is tried without early exit.
- Secrets shorter than 16 bytes are refused at startup.

## Issuing keys

```bash
export GQL_TENANT_KEY_SECRET=$(openssl rand -hex 32)   # avoid the process list
./gql-firewall --tenant-key-issue acme --tenant-key-ttl 720h
# v1.eyJ0aWQiOiJhY21lIiwiZXhwIjoxNzMw...
```

`--tenant-key-issue` prints the key to stdout and exits; it does not start a
server. The secret may also be passed with `--tenant-key-secret` (comma
separated, newest first) instead of the environment variable.

## Deploying verified mode

```bash
GQL_TENANT_KEY_SECRET_PREV=... \
GQL_TENANT_KEY_SECRET=$(openssl rand -hex 32) \
./gql-firewall \
  --tenant-mode=hmac \
  --tenant-key-secret "$NEW,$OLD" \
  --opa-embed opa-policies/graphql.rego
```

Requests without any key remain anonymous and are evaluated against the global
parameters. To require credentials for every request, pair verified mode with a
policy rule that denies anonymous traffic.

## Migration from header mode (three stages)

Header mode is often already behind an authenticating gateway. Move to signed
keys without a flag day:

1. **Dual accept.** Run `--tenant-mode=hmac --tenant-allow-unsigned`. Signed
   keys are verified; unsigned keys are still accepted but labelled
   `source="header"`. Signed traffic starts flowing as clients migrate.
2. **Observe and enforce.** Watch
   `gql_firewall_tenant_identity_total{source="header"}` until it reaches zero,
   then set `require_verified_tenant: true` in the policy parameters. Unsigned
   traffic now returns `403` from policy while still being counted separately
   from `401`s.
3. **Close the door.** Drop `--tenant-allow-unsigned`. Unsigned keys now get
   `401` before reaching policy.

## Rotation

Add the new secret first, keep the old one until every client has reissued:

```bash
--tenant-key-secret "$NEW,$OLD"    # both verify; new keys sign with $NEW
```

Then remove `$OLD`. Rotation never requires downtime, and `hmac.Equal` compares
every secret so timing does not reveal which one matched.

## Responses

| Situation | Status | Body |
|---|---|---|
| Key present but forged, malformed or expired | `401` | `{"error": "invalid tenant credentials"}` |
| Key valid, tenant not registered (and tenants exist) | `403` | `reason: unknown tenant is not registered` |
| Key valid, tenant registered | forwarded | — |
| No key | forwarded as anonymous | — |

The `401` never echoes the presented value: a client that sent a raw secret in
the `X-API-Key` header will not see it reflected. The reason is logged
server-side.

## Telemetry

- `gql_firewall_tenant_identity_total{source,result}` — `result` is `present`,
  `absent` or `invalid`. Alert on a sustained `invalid` rate (probing, or a
  client with a retired secret) and on `source="header"` after stage 3.
- `gql_firewall_requests_blocked_total{reason="unknown_tenant"}` — valid
  signature for a tenant this firewall has no configuration for.

## See also

- `--unknown-tenant` (default `deny`) in the README: unregistered tenants are
  refused once any tenant is registered; single-tenant deployments are
  unaffected.
- `--opa-cache-max-entries`: the decision cache is bounded and keyed on tenant
  **and** identity source, so a verdict cannot be replayed across assurance
  levels.
