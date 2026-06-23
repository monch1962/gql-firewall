package opa

import "github.com/monch1962/gql-firewall/internal/parser"

// Input is the extended query information sent to OPA for evaluation.
// All fields the Rego policies reference must be populated here.
// Params and TenantConfig are populated by the Go sidecar from the DataStore
// so the same policy works for both embedded and sidecar modes.
type Input struct {
	OperationType          string                 `json:"operation_type"`
	OperationName          string                 `json:"operation_name,omitempty"`
	Depth                  int                    `json:"depth"`
	FieldCount             int                    `json:"field_count"`
	FieldPaths             []string               `json:"field_paths"`
	TenantID               string                 `json:"tenant_id,omitempty"`
	Directives             int                    `json:"directives,omitempty"`
	BatchSize              int                    `json:"batch_size,omitempty"`
	ArgumentDepth          int                    `json:"argument_depth,omitempty"`
	ListsRequested         int                    `json:"lists_requested,omitempty"`
	FragmentSpreadCount    int                    `json:"fragment_spread_count,omitempty"`
	QueryHash              string                 `json:"query_hash,omitempty"`
	RequirePersistedQueries bool                  `json:"require_persisted_queries,omitempty"`
	FieldAllowlist         []string               `json:"field_allowlist,omitempty"`
	Params                 map[string]interface{} `json:"params,omitempty"`
	TenantConfig           map[string]interface{} `json:"tenant_config,omitempty"`
}

// BuildInput converts a parser.QueryInfo into the extended OPA Input.
// Fields not yet populated by the parser are left as zero values.
func BuildInput(info *parser.QueryInfo, store *DataStore) *Input {
	input := &Input{
		OperationType:          info.OperationType,
		OperationName:          info.OperationName,
		Depth:                  info.Depth,
		FieldCount:             info.FieldCount,
		FieldPaths:             info.FieldPaths,
		TenantID:               info.TenantID,
		Directives:             0,
		BatchSize:              0,
		ArgumentDepth:          0,
		ListsRequested:         0,
		FragmentSpreadCount:    0,
		QueryHash:              "",
		RequirePersistedQueries: false,
		FieldAllowlist:         nil,
	}
	if store != nil {
		input.Params = store.GetParams()
		if info.TenantID != "" {
			input.TenantConfig = store.GetTenant(info.TenantID)
		}
	}
	return input
}
