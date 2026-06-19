// Package tenant provides per-tenant configuration isolation for the GraphQL firewall.
// Tenants are identified by API key (X-API-Key header) or JWT claims,
// and each tenant can have its own rules configuration.
package tenant

import (
	"crypto/subtle"
	"fmt"
	"sync"

	"github.com/monch1962/gql-firewall/internal/rules"
)

// Store holds per-tenant rules configurations.
type Store struct {
	mu       sync.RWMutex
	tenants  map[string]*rules.Config
	defaults *rules.Config
}

// New creates a tenant store with an optional default config.
func New(defaults *rules.Config) *Store {
	return &Store{
		tenants:  make(map[string]*rules.Config),
		defaults: defaults,
	}
}

// Get returns the rules config for a tenant ID.
// Falls back to the default config if no tenant-specific config exists.
func (s *Store) Get(tenantID string) *rules.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if cfg, ok := s.tenants[tenantID]; ok {
		return cfg
	}
	return s.defaults
}

// Set creates or updates a tenant's rules configuration.
func (s *Store) Set(tenantID string, cfg *rules.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tenants[tenantID] = cfg
}

// Delete removes a tenant's configuration (falls back to default).
func (s *Store) Delete(tenantID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tenants, tenantID)
}

// List returns all configured tenant IDs.
func (s *Store) List() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.tenants))
	for id := range s.tenants {
		ids = append(ids, id)
	}
	return ids
}

// Count returns the number of configured tenants.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tenants)
}

// ExtractTenantID extracts a tenant identifier from an API key header.
// The expected format is "X-API-Key: <tenant_id>_<key>".
// Uses the LAST underscore as separator so tenant IDs can contain underscores
// (e.g. "my_tenant" is valid with key "my_tenant_secret123").
// If the key has no underscore, the entire key is used as the tenant ID.
func ExtractTenantID(apiKey string) string {
	if apiKey == "" {
		return ""
	}
	// Walk backwards to find the LAST underscore
	for i := len(apiKey) - 1; i > 0; i-- {
		if apiKey[i] == '_' && i < len(apiKey)-1 {
			return apiKey[:i]
		}
	}
	return apiKey
}

// ErrTenantNotFound is returned when a tenant operation references an unknown ID.
var ErrTenantNotFound = fmt.Errorf("tenant not found")

// KeyStore maps tenant IDs to expected API key secrets and provides
// constant-time validation of API keys.
type KeyStore struct {
	secrets map[string]string
}

// NewKeyStore creates a KeyStore from a map of tenant IDs to expected secrets.
func NewKeyStore(secrets map[string]string) *KeyStore {
	return &KeyStore{secrets: secrets}
}

// Validate checks whether an API key is valid for a known tenant.
// It extracts the tenant prefix (before the last underscore), looks up the
// expected secret, and compares using constant-time comparison.
// Returns the tenant ID and whether the key is valid.
func (ks *KeyStore) Validate(apiKey string) (tenantID string, ok bool) {
	tenantID = ExtractTenantID(apiKey)
	if tenantID == "" {
		return "", false
	}

	expectedSecret, exists := ks.secrets[tenantID]
	if !exists {
		return "", false
	}

	// No underscore means there's no secret component to validate
	if tenantID == apiKey {
		return "", false
	}

	// Extract secret part: everything after the last underscore
	secret := apiKey[len(tenantID)+1:] // +1 for the underscore

	if subtle.ConstantTimeCompare([]byte(secret), []byte(expectedSecret)) == 1 {
		return tenantID, true
	}
	return "", false
}
