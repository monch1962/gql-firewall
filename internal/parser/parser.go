// Package parser provides GraphQL query analysis — parsing, depth calculation,
// field path extraction, and operation type detection.
package parser

// QueryInfo holds the results of parsing and analysing a GraphQL query.
type QueryInfo struct {
	// OperationType is "query", "mutation", or "subscription".
	OperationType string `json:"operation_type"`
	// OperationName is the optional named operation (e.g. "GetUser").
	OperationName string `json:"operation_name,omitempty"`
	// Depth is the maximum nesting depth of fields in the query.
	Depth int `json:"depth"`
	// FieldCount is the total number of leaf fields requested.
	FieldCount int `json:"field_count"`
	// FieldPaths contains the dot-separated paths of all fields (e.g. "user.profile.email").
	FieldPaths []string `json:"field_paths"`
}

// Parse analyses a raw GraphQL query string and returns structured information
// about its structure, depth, fields, and operation type.
func Parse(query string) (*QueryInfo, error) {
	return parseGraphQL(query)
}
