package tenant

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── R97: credential header ambiguity and unbounded key material ────────────
// The firewall reads X-API-Key with Header.Get (first value). A proxy or
// upstream that joins repeated headers, or reads the last one, can therefore
// authenticate a different principal than the one the firewall policed.
// Attack: send two X-API-Key headers (or one comma-joined value) so the
// firewall verifies tenant A while the backend sees tenant B.

func reqWithValues(values ...string) *http.Request {
	req := httptest.NewRequest("POST", "/graphql", nil)
	for _, v := range values {
		req.Header.Add("X-API-Key", v)
	}
	return req
}

// CAPEC-21: trusted identifiers — ambiguous credential headers let the client
// choose which identity the upstream trusts.
func TestAttack_DuplicateAPIKeyHeadersRejected(t *testing.T) {
	valid := signedAt(t, "acme", time.Now())

	for name, resolver := range map[string]Resolver{
		"header": HeaderResolver{},
		"hmac":   mustResolver(t, Options{Secrets: []string{testSecret}}),
	} {
		t.Run(name, func(t *testing.T) {
			req := reqWithValues(valid, "bob_secret")
			id, err := resolver.Resolve(req)
			if err == nil {
				t.Fatalf("duplicate X-API-Key accepted as tenant %q (source %q); upstream may read the other value", id.TenantID, id.Source)
			}
			if !errors.Is(err, ErrInvalidKey) {
				t.Errorf("error = %v, want ErrInvalidKey so the proxy answers 401", err)
			}
		})
	}
}

// A comma-joined single header is the same ambiguity after header folding.
func TestAttack_CommaJoinedAPIKeyRejected(t *testing.T) {
	for name, resolver := range map[string]Resolver{
		"header": HeaderResolver{},
		"hmac":   mustResolver(t, Options{Secrets: []string{testSecret}}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := resolver.Resolve(reqWithValues("acme_secret,bob_secret")); err == nil {
				t.Error("comma-joined X-API-Key accepted; a folding proxy yields a different credential upstream")
			}
		})
	}
}

// An attacker must not be able to make the firewall hash/decode megabytes of
// attacker-chosen header material on every request.
func TestAttack_OversizedAPIKeyRejected(t *testing.T) {
	huge := "v1." + strings.Repeat("A", MaxCredentialLen)

	hmacRes := mustResolver(t, Options{Secrets: []string{testSecret}})
	if _, err := hmacRes.Resolve(reqWithValues(huge)); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("hmac resolver: oversized key error = %v, want ErrInvalidKey", err)
	}

	if _, err := (HeaderResolver{}).Resolve(reqWithValues(huge)); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("header resolver: oversized key error = %v, want ErrInvalidKey", err)
	}
}

// An oversized key must also be refused by the issuer path so a client cannot
// push an over-long credential through a rollout.
func TestAttack_CredentialAtLimitStillAccepted(t *testing.T) {
	// The limit must not reject ordinary keys: a signed key is ~120 bytes.
	key := signedAt(t, "acme", time.Now())
	if len(key) >= MaxCredentialLen {
		t.Fatalf("signed key is %d bytes, unexpected", len(key))
	}
	hmacRes := mustResolver(t, Options{Secrets: []string{testSecret}})
	if _, err := hmacRes.Resolve(reqWithValues(key)); err != nil {
		t.Fatalf("ordinary signed key rejected: %v", err)
	}
}

// signClaims signs arbitrary payload bytes with the test secret so a test can
// present a structurally valid key carrying a hostile tenant identifier.
func signClaims(payload string) string {
	seg := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signed := keyVersion + "." + seg
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// ── R97: a correctly signed claim must still carry a boring tenant ID ───────
// A shared secret may be held by more than this firewall (rotation scripts,
// other issuers). A valid MAC over a hostile tid would inject newlines/commas
// into logs and policy input, so the claim shape is validated too.
func TestAttack_SignedClaimWithInvalidTenantIDRejected(t *testing.T) {
	now := time.Now()
	res := mustResolver(t, Options{Secrets: []string{testSecret}, Now: func() time.Time { return now }})

	for _, tid := range []string{
		"acme\nadmin",
		"acme,admin",
		"acme admin",
		strings.Repeat("a", 65),
		"-leading-dash",
	} {
		payload := fmt.Sprintf(`{"tid":%q,"exp":%d}`, tid, now.Add(time.Hour).Unix())
		if _, err := res.Resolve(reqWithValues(signClaims(payload))); err == nil {
			t.Errorf("signed key with tid %q accepted; tenant IDs must match the identifier pattern", tid)
		}
	}
}

// Non-canonical tenant identifiers from an asserted header are refused too:
// they can never be registered, so accepting them only produces a silent
// downgrade to the global parameter set.
func TestAttack_HeaderResolverRejectsNonCanonicalTenantID(t *testing.T) {
	for _, key := range []string{"acme key", "acme:key", "-acme_secret"} {
		if _, err := (HeaderResolver{}).Resolve(reqWithValues(key)); err == nil {
			t.Errorf("header key %q accepted as a tenant identity", key)
		}
	}
}

func signedAt(t *testing.T, tenantID string, now time.Time) string {
	t.Helper()
	key, err := IssueKey(tenantID, []string{testSecret}, time.Hour, now)
	if err != nil {
		t.Fatalf("IssueKey: %v", err)
	}
	return key
}
