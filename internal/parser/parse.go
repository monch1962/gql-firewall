package parser

import (
	"crypto/sha256"
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

	// Compute query hash
	hash := sha256.Sum256([]byte(query))

	info := &QueryInfo{
		FieldPaths:    []string{},
		BatchSize:     len(doc.Operations),
		QueryHash:     fmt.Sprintf("%x", hash[:8]),
		FragmentCount: len(doc.Fragments),
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

		// Count operation-level directives
		currentInfo.OperationDirectives += len(op.Directives)

		// Extract variable definitions
		currentInfo.VariableCount = len(op.VariableDefinitions)
		for _, vd := range op.VariableDefinitions {
			if vd.DefaultValue != nil {
				currentInfo.HasDefaultVariables = true
				break
			}
		}

		// Track visited fragments to prevent infinite recursion on circular refs
		currentInfo.FieldPaths = []string{}
		visited := make(map[string]bool)
		walkSelections(op.SelectionSet, "", 0, currentInfo, doc, visited)

		// Count fragment definition directives (for inline + named fragments,
		// directives are counted inside walkSelections; here we count directives
		// on the fragment definitions themselves)
		for _, frag := range doc.Fragments {
			currentInfo.Directives += len(frag.Directives)
		}

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
		if currentInfo.Directives > info.Directives {
			info.Directives = currentInfo.Directives
		}
		if currentInfo.ArgumentDepth > info.ArgumentDepth {
			info.ArgumentDepth = currentInfo.ArgumentDepth
		}
		if currentInfo.ListsRequested > info.ListsRequested {
			info.ListsRequested = currentInfo.ListsRequested
		}
		if currentInfo.FragmentSpreadCount > info.FragmentSpreadCount {
			info.FragmentSpreadCount = currentInfo.FragmentSpreadCount
		}
		if currentInfo.VariableCount > info.VariableCount {
			info.VariableCount = currentInfo.VariableCount
		}
		if currentInfo.OperationDirectives > info.OperationDirectives {
			info.OperationDirectives = currentInfo.OperationDirectives
		}
		if currentInfo.InlineFragmentTypesCount > info.InlineFragmentTypesCount {
			info.InlineFragmentTypesCount = currentInfo.InlineFragmentTypesCount
		}
		if currentInfo.HasDefaultVariables {
			info.HasDefaultVariables = true
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

			// Count directives on this field
			info.Directives += len(s.Directives)

			// Measure argument depth
			for _, arg := range s.Arguments {
				argDepth := measureValueDepth(arg.Value, 1)
				if argDepth > info.ArgumentDepth {
					info.ArgumentDepth = argDepth
				}
			}

			// Heuristic: field names ending in 's' (plural) are likely lists
			if len(fieldName) > 1 && fieldName[len(fieldName)-1] == 's' {
				info.ListsRequested++
			}

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
			info.FragmentSpreadCount++

			// Count directives on this inline fragment
			info.Directives += len(s.Directives)

			// Track unique type conditions for inline fragments
			if s.TypeCondition != "" {
				info.InlineFragmentTypesCount++
			}

			if s.SelectionSet != nil {
				walkSelections(s.SelectionSet, prefix, depth, info, doc, visited)
			}

		case *ast.FragmentSpread:
			info.FragmentSpreadCount++

			// Count directives on this fragment spread
			info.Directives += len(s.Directives)

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

// measureValueDepth recursively measures the maximum nesting depth of argument values.
// Handles all GraphQL value types: Variable, IntValue, FloatValue, StringValue,
// BooleanValue, NullValue, EnumValue, ListValue, ObjectValue.
func measureValueDepth(v *ast.Value, depth int) int {
	if v == nil {
		return depth
	}
	maxDepth := depth
	for _, child := range v.Children {
		if child.Value != nil {
			childDepth := measureValueDepth(child.Value, depth+1)
			if childDepth > maxDepth {
				maxDepth = childDepth
			}
		}
	}
	// Check VariableDefinition.DefaultValue (the $var reference has a back-link
	// to its definition, and the definition may have a nested default value)
	if v.VariableDefinition != nil && v.VariableDefinition.DefaultValue != nil {
		defaultDepth := measureValueDepth(v.VariableDefinition.DefaultValue, depth+1)
		if defaultDepth > maxDepth {
			maxDepth = defaultDepth
		}
	}
	return maxDepth
}
