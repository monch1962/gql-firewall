package opa

import (
	"encoding/json"
	"sync"
)

// DataStore holds OPA parameters and tenant configurations.
// Used by the embedded evaluator to inject data into Rego policies.
// For sidecar mode, these are pushed to the OPA HTTP API instead.
type DataStore struct {
	mu       sync.RWMutex
	params   map[string]interface{}
	tenants  map[string]map[string]interface{}
}

// NewDataStore creates an empty data store.
func NewDataStore() *DataStore {
	return &DataStore{
		params:  make(map[string]interface{}),
		tenants: make(map[string]map[string]interface{}),
	}
}

// SetParams replaces all parameters with the given map.
func (s *DataStore) SetParams(params map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.params = params
}

// GetParams returns a copy of the current parameters.
func (s *DataStore) GetParams() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[string]interface{}, len(s.params))
	for k, v := range s.params {
		cp[k] = v
	}
	return cp
}

// SetTenant creates or updates a tenant's configuration.
func (s *DataStore) SetTenant(tenantID string, cfg map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tenants[tenantID] = cfg
}

// DeleteTenant removes a tenant's configuration.
func (s *DataStore) DeleteTenant(tenantID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tenants, tenantID)
}

// GetTenant returns a tenant's configuration, or nil.
func (s *DataStore) GetTenant(tenantID string) map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg, ok := s.tenants[tenantID]
	if !ok {
		return nil
	}
	return cfg
}

// ListTenants returns all configured tenant IDs.
func (s *DataStore) ListTenants() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.tenants))
	for id := range s.tenants {
		ids = append(ids, id)
	}
	return ids
}

// CountTenants returns the number of configured tenants.
func (s *DataStore) CountTenants() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tenants)
}

// LoadParamsFromJSON loads parameters from a JSON byte slice.
func (s *DataStore) LoadParamsFromJSON(data []byte) error {
	var params map[string]interface{}
	if err := json.Unmarshal(data, &params); err != nil {
		return err
	}
	s.SetParams(params)
	return nil
}
