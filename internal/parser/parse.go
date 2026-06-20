// Package parser provides GraphQL query analysis — parsing, depth calculation,
// field path extraction, and operation type detection.
package parser

import (
	"fmt"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

func parseGraphQL(query string) (*QueryInfo, error) {
	if query == "" {
		return nil, fmt.Errorf("empty query")
	}

	doc, err := parser.ParseQuery(&ast.Source{
		Input: query,
		Name:  "query",
	})
	if err != nil {
		return nil, fmt.Errorf("parsing query: %w", err)
	}

	if len(doc.Operations) == 0 {
		return nil, fmt.Errorf("no operations in query")
	}

	// GraphQL spec: when multiple operations exist, they must all be named
	if len(doc.Operations) > 1 {
		for _, op := range doc.Operations {
			if op.Name == "" {
				return nil, fmt.Errorf("multiple operations require unique operation names")
			}
		}
	}

	info := &QueryInfo{
		FieldPaths: []string{},
	}

	// Iterate ALL operations for full analysis
	for _, op := range doc.Operations {
		currentInfo := &QueryInfo{}
		if op.Name != "" {
			currentInfo.OperationName = op.Name
		}
		switch op.Operation {
		case ast.Query:
			currentInfo.OperationType = "query"
		case ast.Mutation:
			currentInfo.OperationType = "mutation"
		case ast.Subscription:
			currentInfo.OperationType = "subscription"
		default:
			currentInfo.OperationType = "query"
		}

		// Track visited fragments to prevent infinite recursion on circular refs
		currentInfo.FieldPaths = []string{}
		visited := make(map[string]bool)
		walkSelections(op.SelectionSet, "", 0, currentInfo, doc, visited)

		// Aggregate — use the first operation's name/type as representative
		if info.OperationName == "" {
			info.OperationName = currentInfo.OperationName
		}
		if info.OperationType == "" {
			info.OperationType = currentInfo.OperationType
		}

		// Take worst-case values across all operations
		if currentInfo.Depth > info.Depth {
			info.Depth = currentInfo.Depth
		}
		if currentInfo.FieldCount > info.FieldCount {
			info.FieldCount = currentInfo.FieldCount
		}
		info.FieldPaths = append(info.FieldPaths, currentInfo.FieldPaths...)
	}

	return info, nil
}

func walkSelections(selections ast.SelectionSet, prefix string, depth int, info *QueryInfo, doc *ast.QueryDocument, visited map[string]bool) {
	for _, sel := range selections {
		switch s := sel.(type) {
		case *ast.Field:
			fieldName := s.Name
			if s.Alias != "" {
				fieldName = s.Alias
			}
			info.FieldCount++

			path := fieldName
			if prefix != "" {
				path = prefix + "." + fieldName
			}
			info.FieldPaths = append(info.FieldPaths, path)

			newDepth := depth + 1
			if newDepth > info.Depth {
				info.Depth = newDepth
			}

			if s.SelectionSet != nil {
				walkSelections(s.SelectionSet, path, newDepth, info, doc, visited)
			}

		case *ast.InlineFragment:
			if s.SelectionSet != nil {
				walkSelections(s.SelectionSet, prefix, depth, info, doc, visited)
			}

		case *ast.FragmentSpread:
			fragmentName := s.Name
			// Prevent infinite recursion on circular fragment references
			if visited[fragmentName] {
				continue
			}
			visited[fragmentName] = true

			fragment := doc.Fragments.ForName(fragmentName)
			if fragment != nil && fragment.SelectionSet != nil {
				walkSelections(fragment.SelectionSet, prefix, depth, info, doc, visited)
			}
		}
	}
}
