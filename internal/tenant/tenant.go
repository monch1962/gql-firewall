// Package tenant establishes the tenant identity for an incoming request and
// records how that identity was established.
//
// The trust model matters: a tenant ID decides which policy configuration is
// applied, so the firewall must be explicit about whether that identity is
// proven or merely asserted.
package tenant

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Source records how a tenant identity was established.
type Source string

const (
	// SourceHeader means the tenant was parsed out of the client-supplied
	// X-API-Key header. It is asserted, not proven.
	SourceHeader Source = "header"
	// SourceHMAC means the tenant was carried in a key signed by this firewall
	// and verified against a configured secret.
	SourceHMAC Source = "hmac"
	// SourceNone means no tenant identity was presented.
	SourceNone Source = "none"
)

// Errors returned when a presented key cannot be trusted.
var (
	ErrInvalidKey = errors.New("invalid tenant key")
	ErrExpiredKey = errors.New("expired tenant key")
)

// MaxCredentialLen bounds the X-API-Key header before any decoding or MAC work.
// A legitimate signed key is ~120 bytes; anything far larger is an attempt to
// make the firewall hash attacker-chosen material on every request.
const MaxCredentialLen = 4096

// Identity is the tenant identity established for a single request.
type Identity struct {
	TenantID string
	Source   Source
}

// Resolver establishes tenant identity for a request. An error means the
// caller presented credentials that could not be verified.
type Resolver interface {
	Resolve(r *http.Request) (Identity, error)
}

// Options configures resolver construction.
type Options struct {
	// Secrets are the HMAC secrets accepted for signed keys, newest first.
	Secrets []string
	// AllowUnsigned accepts unsigned keys during migration, labelling them
	// with SourceHeader so policies can still refuse them.
	AllowUnsigned bool
	// ClockSkew tolerates small clock differences when checking expiry.
	ClockSkew time.Duration
	// Now overrides the clock (tests only).
	Now func() time.Time
}

// credential returns the request's single X-API-Key value, or "" when absent.
//
// Repeated headers (or one comma-joined value) are refused: Header.Get returns
// only the first value, while a folding proxy or the upstream may read the last
// one. Accepting ambiguity lets a client have the firewall police tenant A
// while the backend authenticates tenant B (CAPEC-21, trusted identifiers).
// The value is also length-bounded and character-checked before any decoding or
// MAC work, so an attacker cannot make the firewall hash attacker-chosen
// material on every request.
func credential(r *http.Request) (string, error) {
	values := r.Header.Values("X-API-Key")
	if len(values) == 0 {
		return "", nil
	}
	if len(values) > 1 {
		return "", fmt.Errorf("%w: multiple X-API-Key headers are ambiguous", ErrInvalidKey)
	}
	key := values[0]
	if len(key) > MaxCredentialLen {
		return "", fmt.Errorf("%w: credential exceeds %d bytes", ErrInvalidKey, MaxCredentialLen)
	}
	for i := 0; i < len(key); i++ {
		if c := key[i]; c <= ' ' || c > '~' || c == ',' {
			return "", fmt.Errorf("%w: credential contains invalid characters", ErrInvalidKey)
		}
	}
	return key, nil
}

// canonicalTenantID reports whether id is a well-formed tenant identifier.
// Every tenant ID reaches logs and policy input, and only canonical IDs can be
// registered, so a non-canonical claim would otherwise silently fall through
// to the global parameter set.
func canonicalTenantID(id string) bool {
	return tenantIDPattern.MatchString(id)
}

// HeaderResolver derives the tenant from the X-API-Key header without
// verification. It is only appropriate when a trusted gateway has already
// authenticated the caller and stripped any inbound X-API-Key header; it is
// not a security boundary on its own.
type HeaderResolver struct{}

// Resolve implements Resolver.
func (HeaderResolver) Resolve(r *http.Request) (Identity, error) {
	key, err := credential(r)
	if err != nil {
		return Identity{Source: SourceHeader}, err
	}
	if key == "" {
		return Identity{Source: SourceNone}, nil
	}
	id := ExtractTenantID(key)
	if !canonicalTenantID(id) {
		return Identity{Source: SourceHeader}, fmt.Errorf("%w: tenant ID is not a valid identifier", ErrInvalidKey)
	}
	return Identity{TenantID: id, Source: SourceHeader}, nil
}

// ResolverFor returns the resolver for a configured mode name. Unimplemented
// modes fail closed at startup rather than silently degrading to the unverified
// header resolver.
func ResolverFor(mode string, opts Options) (Resolver, error) {
	switch mode {
	case "", "header":
		return HeaderResolver{}, nil
	case "hmac":
		return newHMACResolver(opts)
	default:
		return nil, fmt.Errorf("tenant mode %q is not implemented (available: header, hmac; jwt and mtls are planned)", mode)
	}
}

// ExtractTenantID derives a tenant identifier from an API key.
// The scheme is "<tenant>_<secret>"; the tenant is everything before the final
// underscore segment. The value is client-controlled and unverified.
func ExtractTenantID(apiKey string) string {
	if apiKey == "" {
		return ""
	}
	for i := len(apiKey) - 1; i >= 0; i-- {
		if apiKey[i] == '_' && hasLeadingContent(apiKey[:i]) && i < len(apiKey)-1 {
			return apiKey[:i]
		}
	}
	return apiKey
}

func hasLeadingContent(s string) bool {
	for i := range len(s) {
		if s[i] != '_' && s[i] != ' ' {
			return true
		}
	}
	return false
}
