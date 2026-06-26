package opa

import (
	"encoding/json"

	"github.com/monch1962/gql-firewall/internal/parser"
)

// Input is the extended query information sent to OPA for evaluation.
type Input struct {
	OperationType            string                 `json:"operation_type"`
	OperationName            string                 `json:"operation_name,omitempty"`
	Depth                    int                    `json:"depth"`
	FieldCount               int                    `json:"field_count"`
	FieldPaths               []string               `json:"field_paths"`
	TenantID                 string                 `json:"tenant_id,omitempty"`
	Directives               int                    `json:"directives,omitempty"`
	BatchSize                int                    `json:"batch_size,omitempty"`
	ArgumentDepth            int                    `json:"argument_depth,omitempty"`
	ListsRequested           int                    `json:"lists_requested,omitempty"`
	FragmentSpreadCount      int                    `json:"fragment_spread_count,omitempty"`
	QueryHash                string                 `json:"query_hash,omitempty"`
	VariableCount            int                    `json:"variable_count,omitempty"`
	HasDefaultVariables      bool                   `json:"has_default_variables,omitempty"`
	OperationDirectives      int                    `json:"operation_directives,omitempty"`
	InlineFragmentTypesCount int                    `json:"inline_fragment_types_count,omitempty"`
	FragmentCount            int                    `json:"fragment_count,omitempty"`
	RequestVariables         map[string]interface{} `json:"request_variables,omitempty"`
	RequirePersistedQueries  bool                   `json:"require_persisted_queries,omitempty"`
	FieldAllowlist           []string               `json:"field_allowlist,omitempty"`
	Params                   map[string]interface{} `json:"params,omitempty"`
	TenantConfig             map[string]interface{} `json:"tenant_config,omitempty"`
}

// BuildInput converts a parser.QueryInfo into the extended OPA Input.
func BuildInput(info *parser.QueryInfo, store *DataStore) *Input {
	input := &Input{
		OperationType:            info.OperationType,
		OperationName:            info.OperationName,
		Depth:                    info.Depth,
		FieldCount:               info.FieldCount,
		FieldPaths:               info.FieldPaths,
		TenantID:                 info.TenantID,
		Directives:               info.Directives,
		BatchSize:                info.BatchSize,
		ArgumentDepth:            info.ArgumentDepth,
		ListsRequested:           info.ListsRequested,
		FragmentSpreadCount:      info.FragmentSpreadCount,
		QueryHash:                info.QueryHash,
		VariableCount:            info.VariableCount,
		HasDefaultVariables:      info.HasDefaultVariables,
		OperationDirectives:      info.OperationDirectives,
		InlineFragmentTypesCount: info.InlineFragmentTypesCount,
		FragmentCount:            info.FragmentCount,
		RequirePersistedQueries:  false,
		FieldAllowlist:           nil,
	}
	if len(info.RequestVariables) > 0 {
		var vars map[string]interface{}
		if err := json.Unmarshal(info.RequestVariables, &vars); err == nil {
			input.RequestVariables = vars
		}
	}
	if store != nil {
		input.Params = store.GetParams()
		if info.TenantID != "" {
			input.TenantConfig = store.GetTenant(info.TenantID)
		}
	}
	return input
}
