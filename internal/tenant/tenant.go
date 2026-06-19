// Package tenant provides per-tenant configuration isolation for the GraphQL firewall.
// Tenants are identified by API key (X-API-Key header) or JWT claims,
// and each tenant can have its own rules configuration.
package tenant

import (
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
// If the key has no underscore prefix, the entire key is used as the tenant ID.
func ExtractTenantID(apiKey string) string {
	if apiKey == "" {
		return ""
	}
	// Support format: "tenant_id_secretkey" — extract the tenant prefix
	for i := 0; i < len(apiKey); i++ {
		if apiKey[i] == '_' && i > 0 && i < len(apiKey)-1 {
			return apiKey[:i]
		}
	}
	return apiKey
}

// ErrTenantNotFound is returned when a tenant operation references an unknown ID.
var ErrTenantNotFound = fmt.Errorf("tenant not found")
