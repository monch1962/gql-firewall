// Package parser provides GraphQL query analysis — parsing, depth calculation,
// field path extraction, operation type detection, and SDL schema validation.
package parser

import (
	"fmt"
	"os"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
	"github.com/vektah/gqlparser/v2/validator"
)

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
	// TenantID identifies the tenant for per-tenant policy isolation.
	TenantID string `json:"tenant_id,omitempty"`
}

// SchemaInfo holds a compiled GraphQL schema for schema-aware validation.
type SchemaInfo struct {
	Schema    *ast.Schema
	TypeCount int
}

// LoadSchema reads and compiles a GraphQL SDL schema file for validation.
func LoadSchema(path string) (*SchemaInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading schema file: %w", err)
	}

	source := &ast.Source{
		Input: string(data),
		Name:  path,
	}

	schema, err := validator.ValidateSchemaDocument(&ast.SchemaDocument{})
	if err != nil {
		// Try loading via SchemaDocument parser instead
		doc, parseErr := parser.ParseSchema(source)
		if parseErr != nil {
			return nil, fmt.Errorf("parsing schema: %w", parseErr)
		}
		s, sErr := validator.ValidateSchemaDocument(doc)
		if sErr != nil {
			return nil, fmt.Errorf("validating schema: %w", sErr)
		}
		schema = s
	}

	return &SchemaInfo{
		Schema:    schema,
		TypeCount: len(schema.Types),
	}, nil
}

// Validate checks if the query's fields exist in the schema.
func (s *SchemaInfo) Validate(info *QueryInfo) (bool, string) {
	// Basic validation: check that the top-level fields exist
	for _, path := range info.FieldPaths {
		// Check each path segment against the schema
		parts := splitPath(path)
		if len(parts) == 0 {
			continue
		}

		// Check first segment as a top-level field on the Query type
		queryType := s.Schema.Query
		if queryType == nil {
			continue
		}

		field := queryType.Fields.ForName(parts[0])
		if field == nil {
			return false, fmt.Sprintf("field %q does not exist on Query type", parts[0])
		}
	}

	return true, ""
}

// Parse analyses a raw GraphQL query string and returns structured information
// about its structure, depth, fields, and operation type.
func Parse(query string) (*QueryInfo, error) {
	return parseGraphQL(query)
}

func splitPath(path string) []string {
	var parts []string
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || path[i] == '.' {
			if i > start {
				parts = append(parts, path[start:i])
			}
			start = i + 1
		}
	}
	return parts
}
