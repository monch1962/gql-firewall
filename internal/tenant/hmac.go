package tenant

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	keyVersion = "v1"
	// minSecretLen is the shortest accepted HMAC secret. Shorter secrets are
	// guessable and brute-forceable offline from a single captured key.
	minSecretLen = 16
)

// tenantIDPattern keeps issued tenant identifiers boring: they appear in logs,
// metrics and policy input, so no whitespace, quotes or separators.
var tenantIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// claims is the signed payload of a tenant key.
type claims struct {
	TenantID  string `json:"tid"`
	ExpiresAt int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
}

// HMACResolver verifies keys of the form v1.<payload>.<mac>, where the MAC is
// HMAC-SHA256 over "v1.<payload>" with a configured secret.
type HMACResolver struct {
	secrets       [][]byte
	allowUnsigned bool
	skew          time.Duration
	now           func() time.Time
}

func newHMACResolver(opts Options) (Resolver, error) {
	if len(opts.Secrets) == 0 {
		return nil, errors.New("tenant mode hmac requires --tenant-key-secret")
	}
	secrets := make([][]byte, 0, len(opts.Secrets))
	for i, s := range opts.Secrets {
		if len(s) < minSecretLen {
			return nil, fmt.Errorf("tenant key secret #%d is too short: need at least %d bytes", i+1, minSecretLen)
		}
		secrets = append(secrets, []byte(s))
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &HMACResolver{
		secrets:       secrets,
		allowUnsigned: opts.AllowUnsigned,
		skew:          opts.ClockSkew,
		now:           now,
	}, nil
}

// Resolve implements Resolver. Unsigned keys are rejected unless the resolver
// was built with AllowUnsigned (migration), in which case they are accepted but
// stay labelled SourceHeader so policy can still refuse them.
func (h *HMACResolver) Resolve(r *http.Request) (Identity, error) {
	key, err := credential(r)
	if err != nil {
		return Identity{Source: SourceHeader}, err
	}
	if key == "" {
		return Identity{Source: SourceNone}, nil
	}
	if !strings.HasPrefix(key, keyVersion+".") {
		if h.allowUnsigned {
			id := ExtractTenantID(key)
			if !canonicalTenantID(id) {
				return Identity{Source: SourceHeader}, fmt.Errorf("%w: tenant ID is not a valid identifier", ErrInvalidKey)
			}
			return Identity{TenantID: id, Source: SourceHeader}, nil
		}
		return Identity{Source: SourceHeader}, fmt.Errorf("%w: key is not signed", ErrInvalidKey)
	}

	c, err := h.verify(key)
	if err != nil {
		return Identity{Source: SourceHMAC}, err
	}
	return Identity{TenantID: c.TenantID, Source: SourceHMAC}, nil
}

func (h *HMACResolver) verify(key string) (*claims, error) {
	parts := strings.Split(key, ".")
	if len(parts) != 3 || parts[0] != keyVersion || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("%w: malformed key", ErrInvalidKey)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != sha256.Size {
		return nil, fmt.Errorf("%w: malformed signature", ErrInvalidKey)
	}

	// Verify before parsing: the payload is untrusted until the MAC matches, so
	// no attacker-controlled JSON is decoded on behalf of an unauthenticated
	// caller. Every secret is tried (no early exit) so timing does not reveal
	// which one matched during rotation.
	signed := []byte(keyVersion + "." + parts[1])
	valid := false
	for _, secret := range h.secrets {
		mac := hmac.New(sha256.New, secret)
		mac.Write(signed)
		if hmac.Equal(mac.Sum(nil), sig) {
			valid = true
		}
	}
	if !valid {
		return nil, fmt.Errorf("%w: signature mismatch", ErrInvalidKey)
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: malformed payload", ErrInvalidKey)
	}
	var c claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("%w: malformed payload", ErrInvalidKey)
	}
	if c.TenantID == "" {
		return nil, fmt.Errorf("%w: missing tenant", ErrInvalidKey)
	}
	// A shared secret can be held by other issuers (rotation scripts, sibling
	// services). Even a valid MAC must not smuggle a tenant ID that cannot be
	// registered, because the value reaches logs and policy input verbatim.
	if !canonicalTenantID(c.TenantID) {
		return nil, fmt.Errorf("%w: tenant ID is not a valid identifier", ErrInvalidKey)
	}
	if c.ExpiresAt > 0 && h.now().After(time.Unix(c.ExpiresAt, 0).Add(h.skew)) {
		return nil, fmt.Errorf("%w: expired at %s", ErrExpiredKey,
			time.Unix(c.ExpiresAt, 0).UTC().Format(time.RFC3339))
	}
	return &c, nil
}

// IssueKey mints a signed tenant key. The first secret signs; every configured
// secret verifies, so rotate by adding the new secret, reissuing keys, then
// removing the old one. A ttl of 0 issues a key that never expires.
func IssueKey(tenantID string, secrets []string, ttl time.Duration, now time.Time) (string, error) {
	if !tenantIDPattern.MatchString(tenantID) {
		return "", fmt.Errorf("invalid tenant ID %q: must match %s", tenantID, tenantIDPattern.String())
	}
	if len(secrets) == 0 {
		return "", errors.New("at least one secret is required")
	}
	secret := secrets[0]
	if len(secret) < minSecretLen {
		return "", fmt.Errorf("secret is too short: need at least %d bytes", minSecretLen)
	}

	c := claims{TenantID: tenantID, IssuedAt: now.Unix()}
	if ttl != 0 {
		c.ExpiresAt = now.Add(ttl).Unix()
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("encoding claims: %w", err)
	}
	payloadSeg := base64.RawURLEncoding.EncodeToString(payload)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(keyVersion + "." + payloadSeg))

	return keyVersion + "." + payloadSeg + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
