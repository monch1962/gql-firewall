// Package parser provides GraphQL query analysis — parsing, depth calculation,
// field path extraction, operation type detection, SDL schema validation,
// and attack vector metrics (directives, argument depth, fragment spreads, etc.).
package parser

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
	"github.com/vektah/gqlparser/v2/validator"
)

// QueryInfo holds the results of parsing and analysing a GraphQL query.
type QueryInfo struct {
	OperationType            string          `json:"operation_type"`
	OperationName            string          `json:"operation_name,omitempty"`
	Depth                    int             `json:"depth"`
	FieldCount               int             `json:"field_count"`
	FieldPaths               []string        `json:"field_paths"`
	TenantID                 string          `json:"tenant_id,omitempty"`
	Directives               int             `json:"directives,omitempty"`
	BatchSize                int             `json:"batch_size,omitempty"`
	ArgumentDepth            int             `json:"argument_depth,omitempty"`
	ListsRequested           int             `json:"lists_requested,omitempty"`
	FragmentSpreadCount      int             `json:"fragment_spread_count,omitempty"`
	QueryHash                string          `json:"query_hash,omitempty"`
	VariableCount            int             `json:"variable_count,omitempty"`
	HasDefaultVariables      bool            `json:"has_default_variables,omitempty"`
	OperationDirectives      int             `json:"operation_directives,omitempty"`
	InlineFragmentTypesCount int             `json:"inline_fragment_types_count,omitempty"`
	FragmentCount            int             `json:"fragment_count,omitempty"`
	RequestVariables         json.RawMessage `json:"request_variables,omitempty"`
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
	return LoadSchemaFromBytes(data, path)
}

// LoadSchemaFromString compiles a GraphQL SDL schema from a string (for testing).
func LoadSchemaFromString(schema string) (*SchemaInfo, error) {
	return LoadSchemaFromBytes([]byte(schema), "inline")
}

// LoadSchemaFromBytes compiles a GraphQL SDL schema from raw bytes.
func LoadSchemaFromBytes(data []byte, name string) (*SchemaInfo, error) {
	source := &ast.Source{
		Input: string(data),
		Name:  name,
	}

	doc, err := parser.ParseSchema(source)
	if err != nil {
		return nil, fmt.Errorf("parsing schema: %w", err)
	}

	schema, err := validator.ValidateSchemaDocument(doc)
	if err != nil {
		return nil, fmt.Errorf("validating schema: %w", err)
	}

	return &SchemaInfo{
		Schema:    schema,
		TypeCount: len(schema.Types),
	}, nil
}

// Validate checks if the query's fields exist in the schema.
func (s *SchemaInfo) Validate(info *QueryInfo) (bool, string) {
	for _, path := range info.FieldPaths {
		parts := splitPath(path)
		if len(parts) == 0 {
			continue
		}

		currentType := s.Schema.Query
		if currentType == nil {
			continue
		}

		for i, segment := range parts {
			field := currentType.Fields.ForName(segment)
			if field == nil {
				return false, fmt.Sprintf("field %q does not exist on type %q", segment, currentType.Name)
			}

			if i == len(parts)-1 {
				break
			}

			namedType := resolveNamedType(field.Type)
			if namedType == "" {
				return false, fmt.Sprintf("cannot resolve return type for field %q", segment)
			}

			nextType, ok := s.Schema.Types[namedType]
			if !ok {
				return false, fmt.Sprintf("type %q not found in schema", namedType)
			}
			currentType = nextType
		}
	}
	return true, ""
}

// resolveNamedType unwraps NonNull and List type wrappers to find the base named type.
func resolveNamedType(t *ast.Type) string {
	if t == nil {
		return ""
	}
	if t.NamedType != "" {
		return t.NamedType
	}
	if t.Elem != nil {
		return resolveNamedType(t.Elem)
	}
	return ""
}

// Parse analyses a raw GraphQL query string and returns structured information.
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
