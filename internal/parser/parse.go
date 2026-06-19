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

	source := &ast.Source{
		Input: query,
	}

	doc, err := parser.ParseQuery(source)
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	if len(doc.Operations) == 0 {
		return nil, fmt.Errorf("no operations found")
	}

	op := doc.Operations[0]
	info := &QueryInfo{}

	switch op.Operation {
	case ast.Query:
		info.OperationType = "query"
	case ast.Mutation:
		info.OperationType = "mutation"
	case ast.Subscription:
		info.OperationType = "subscription"
	default:
		info.OperationType = "unknown"
	}

	if op.Name != "" {
		info.OperationName = op.Name
	}

	info.Depth = 0
	info.FieldCount = 0
	info.FieldPaths = []string{}

	walkSelections(op.SelectionSet, "", 0, info, doc)

	return info, nil
}

// walkSelections recursively walks a selection set calculating depth,
// counting fields, and building field paths.
func walkSelections(selections ast.SelectionSet, prefix string, depth int, info *QueryInfo, doc *ast.QueryDocument) {
	for _, sel := range selections {
		switch s := sel.(type) {
		case *ast.Field:
			info.FieldCount++

			path := s.Name
			if prefix != "" {
				path = prefix + "." + s.Name
			}
			info.FieldPaths = append(info.FieldPaths, path)

			currentDepth := depth + 1
			if currentDepth > info.Depth {
				info.Depth = currentDepth
			}

			if len(s.SelectionSet) > 0 {
				walkSelections(s.SelectionSet, path, currentDepth, info, doc)
			}

		case *ast.InlineFragment:
			walkSelections(s.SelectionSet, prefix, depth, info, doc)

		case *ast.FragmentSpread:
			for _, frag := range doc.Fragments {
				if frag.Name == s.Name {
					walkSelections(frag.SelectionSet, prefix, depth, info, doc)
					break
				}
			}
		}
	}
}
