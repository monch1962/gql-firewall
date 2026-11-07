// Package tenant establishes the tenant identity for an incoming request and
// records how that identity was established.
//
// The trust model matters: a tenant ID decides which policy configuration is
// applied, so the firewall must be explicit about whether that identity is
// proven or merely asserted.
package tenant

import (
	"fmt"
	"net/http"
)

// Source records how a tenant identity was established.
type Source string

const (
	// SourceHeader means the tenant was parsed out of the client-supplied
	// X-API-Key header. It is asserted, not proven.
	SourceHeader Source = "header"
	// SourceNone means no tenant identity was presented.
	SourceNone Source = "none"
)

// Identity is the tenant identity established for a single request.
type Identity struct {
	TenantID string
	Source   Source
}

// Resolver establishes tenant identity for a request.
type Resolver interface {
	Resolve(r *http.Request) Identity
}

// HeaderResolver derives the tenant from the X-API-Key header without
// verification. It is only appropriate when a trusted gateway has already
// authenticated the caller and stripped any inbound X-API-Key header; it is
// not a security boundary on its own.
type HeaderResolver struct{}

// Resolve implements Resolver.
func (HeaderResolver) Resolve(r *http.Request) Identity {
	key := r.Header.Get("X-API-Key")
	if key == "" {
		return Identity{Source: SourceNone}
	}
	return Identity{TenantID: ExtractTenantID(key), Source: SourceHeader}
}

// ResolverFor returns the resolver for a configured mode name. Unimplemented
// modes fail closed at startup rather than silently degrading to the unverified
// header resolver.
func ResolverFor(mode string) (Resolver, error) {
	switch mode {
	case "", "header":
		return HeaderResolver{}, nil
	default:
		return nil, fmt.Errorf("tenant mode %q is not implemented (available: header; verified modes hmac/jwt/mtls are planned)", mode)
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
