package tenant

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func hmacReq(key string) *http.Request {
	req := httptest.NewRequest("POST", "/graphql", nil)
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	return req
}

func mustResolver(t *testing.T, opts Options) *HMACResolver {
	t.Helper()
	r, err := ResolverFor("hmac", opts)
	if err != nil {
		t.Fatalf("ResolverFor(hmac) error: %v", err)
	}
	h, ok := r.(*HMACResolver)
	if !ok {
		t.Fatalf("ResolverFor(hmac) returned %T", r)
	}
	return h
}

// ── R96: signed tenant keys ────────────────────────────────────────────────
// A key the firewall issued must resolve to its tenant, with a verified source.

func TestIssueAndResolve_RoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key, err := IssueKey("acme", []string{testSecret}, time.Hour, now)
	if err != nil {
		t.Fatalf("IssueKey: %v", err)
	}
	if !strings.HasPrefix(key, "v1.") {
		t.Errorf("issued key %q does not use the v1 format", key)
	}

	h := mustResolver(t, Options{Secrets: []string{testSecret}, Now: func() time.Time { return now }})
	id, err := h.Resolve(hmacReq(key))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if id.TenantID != "acme" {
		t.Errorf("tenant = %q, want %q", id.TenantID, "acme")
	}
	if id.Source != SourceHMAC {
		t.Errorf("source = %q, want %q — a verified identity must be distinguishable", id.Source, SourceHMAC)
	}
}

// Any change to the payload must invalidate the key.
func TestResolve_TamperedPayload(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key, err := IssueKey("acme", []string{testSecret}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(key, ".")
	forged, _ := json.Marshal(claims{TenantID: "victim", ExpiresAt: now.Add(time.Hour).Unix()})
	parts[1] = base64.RawURLEncoding.EncodeToString(forged)
	tampered := strings.Join(parts, ".")

	h := mustResolver(t, Options{Secrets: []string{testSecret}, Now: func() time.Time { return now }})
	if _, err := h.Resolve(hmacReq(tampered)); err == nil {
		t.Fatal("tampered payload accepted: a client can rename its tenant")
	}
}

func TestResolve_TamperedMAC(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key, _ := IssueKey("acme", []string{testSecret}, time.Hour, now)
	parts := strings.Split(key, ".")
	mac, _ := base64.RawURLEncoding.DecodeString(parts[2])
	mac[0] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(mac)

	h := mustResolver(t, Options{Secrets: []string{testSecret}, Now: func() time.Time { return now }})
	if _, err := h.Resolve(hmacReq(strings.Join(parts, "."))); err == nil {
		t.Fatal("tampered MAC accepted")
	}
}

func TestResolve_WrongSecret(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key, _ := IssueKey("acme", []string{"another-secret-value-32-bytes!!"}, time.Hour, now)

	h := mustResolver(t, Options{Secrets: []string{testSecret}, Now: func() time.Time { return now }})
	if _, err := h.Resolve(hmacReq(key)); err == nil {
		t.Fatal("key signed with an unknown secret accepted")
	}
}

// Rotation: a key signed with the previous secret must still verify while both
// secrets are configured, and stop verifying once it is removed.
func TestResolve_SecretRotation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	oldSecret := "old-secret-value-32-bytes-long!!"
	key, _ := IssueKey("acme", []string{oldSecret}, time.Hour, now)

	rotated := mustResolver(t, Options{Secrets: []string{testSecret, oldSecret}, Now: func() time.Time { return now }})
	if _, err := rotated.Resolve(hmacReq(key)); err != nil {
		t.Fatalf("key signed with the previous secret rejected during rotation: %v", err)
	}

	retired := mustResolver(t, Options{Secrets: []string{testSecret}, Now: func() time.Time { return now }})
	if _, err := retired.Resolve(hmacReq(key)); err == nil {
		t.Fatal("key still accepted after its secret was retired")
	}
}

func TestResolve_ExpiredKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key, _ := IssueKey("acme", []string{testSecret}, -time.Minute, now)

	h := mustResolver(t, Options{Secrets: []string{testSecret}, Now: func() time.Time { return now }})
	_, err := h.Resolve(hmacReq(key))
	if err == nil {
		t.Fatal("expired key accepted")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error = %v, want an expiry error", err)
	}
}

func TestResolve_ClockSkewTolerance(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key, _ := IssueKey("acme", []string{testSecret}, -30*time.Second, now)

	tolerant := mustResolver(t, Options{Secrets: []string{testSecret}, ClockSkew: time.Minute, Now: func() time.Time { return now }})
	if _, err := tolerant.Resolve(hmacReq(key)); err != nil {
		t.Errorf("key within the clock-skew window rejected: %v", err)
	}

	strict := mustResolver(t, Options{Secrets: []string{testSecret}, Now: func() time.Time { return now }})
	if _, err := strict.Resolve(hmacReq(key)); err == nil {
		t.Error("key outside the clock-skew window accepted")
	}
}

func TestResolve_NoExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key, _ := IssueKey("acme", []string{testSecret}, 0, now)

	later := now.Add(10 * 365 * 24 * time.Hour)
	h := mustResolver(t, Options{Secrets: []string{testSecret}, Now: func() time.Time { return later }})
	if _, err := h.Resolve(hmacReq(key)); err != nil {
		t.Errorf("non-expiring key rejected: %v", err)
	}
}

func TestResolve_MalformedKeys(t *testing.T) {
	h := mustResolver(t, Options{Secrets: []string{testSecret}})
	cases := []string{
		"not-a-key",
		"v1.only-two",
		"v1..",
		"v1..aaaa",
		"v2.abc.def",
		"v1.!!!.!!!",
		"v1." + base64.RawURLEncoding.EncodeToString([]byte(`{"tid":"acme"}`)) + ".short",
	}
	for _, key := range cases {
		if _, err := h.Resolve(hmacReq(key)); err == nil {
			t.Errorf("malformed key %q accepted", key)
		}
	}
}

// A signature made with a different construction (plain SHA-256 of the payload,
// i.e. no secret) must not verify — algorithm confusion guard.
func TestResolve_RejectsNonHMACSignature(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	payload, _ := json.Marshal(claims{TenantID: "acme", ExpiresAt: now.Add(time.Hour).Unix()})
	payloadSeg := base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte("v1." + payloadSeg))
	forged := fmt.Sprintf("v1.%s.%s", payloadSeg, base64.RawURLEncoding.EncodeToString(sum[:]))

	h := mustResolver(t, Options{Secrets: []string{testSecret}, Now: func() time.Time { return now }})
	if _, err := h.Resolve(hmacReq(forged)); err == nil {
		t.Fatal("unkeyed SHA-256 signature accepted as an HMAC")
	}
}

// ── R96: unsigned keys in hmac mode ────────────────────────────────────────
func TestResolve_UnsignedRejectedInHMACMode(t *testing.T) {
	h := mustResolver(t, Options{Secrets: []string{testSecret}})
	_, err := h.Resolve(hmacReq("acme_secret"))
	if err == nil {
		t.Fatal("unsigned key accepted in hmac mode")
	}
	id, _ := h.Resolve(hmacReq("acme_secret"))
	if id.Source != SourceHeader {
		t.Errorf("source = %q, want %q so telemetry attributes the failure", id.Source, SourceHeader)
	}
}

// Dual-accept during migration: unsigned keys are accepted but stay labelled
// unverified, so a require_verified_tenant policy can still refuse them.
func TestResolve_AllowUnsignedDuringMigration(t *testing.T) {
	h := mustResolver(t, Options{Secrets: []string{testSecret}, AllowUnsigned: true})
	id, err := h.Resolve(hmacReq("acme_secret"))
	if err != nil {
		t.Fatalf("unsigned key rejected despite AllowUnsigned: %v", err)
	}
	if id.TenantID != "acme" || id.Source != SourceHeader {
		t.Errorf("identity = %+v, want tenant acme with source header", id)
	}
}

func TestResolve_AbsentKeyIsAnonymous(t *testing.T) {
	h := mustResolver(t, Options{Secrets: []string{testSecret}})
	id, err := h.Resolve(hmacReq(""))
	if err != nil {
		t.Fatalf("absent key error: %v", err)
	}
	if id.Source != SourceNone || id.TenantID != "" {
		t.Errorf("identity = %+v, want anonymous", id)
	}
}

// ── R96: resolver construction fails closed ────────────────────────────────
func TestResolverFor_HMACRequiresStrongSecret(t *testing.T) {
	if _, err := ResolverFor("hmac", Options{}); err == nil {
		t.Error("hmac mode accepted with no secret")
	}
	if _, err := ResolverFor("hmac", Options{Secrets: []string{"short"}}); err == nil {
		t.Error("hmac mode accepted a secret shorter than the minimum length")
	}
	if _, err := ResolverFor("hmac", Options{Secrets: []string{testSecret}}); err != nil {
		t.Errorf("valid secret rejected: %v", err)
	}
}

func TestIssueKey_RejectsBadTenantID(t *testing.T) {
	for _, id := range []string{"", "has space", "semi;colon", strings.Repeat("a", 65), "-leading-dash"} {
		if _, err := IssueKey(id, []string{testSecret}, time.Hour, time.Now()); err == nil {
			t.Errorf("IssueKey(%q) accepted an invalid tenant ID", id)
		}
	}
	if _, err := IssueKey("acme", nil, time.Hour, time.Now()); err == nil {
		t.Error("IssueKey accepted an empty secret list")
	}
}
