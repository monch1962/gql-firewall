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

	// Fragments are document-level, so their metrics are measured once and
	// replayed for every spread. Analysing them only at their first
	// (shallowest) spread undercounts every deeper one — a depth-limit
	// evasion.
	a := newAnalyzer(doc)

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

		// Track the active fragment stack to cut cycles, and replay memoised
		// fragment metrics at every spread.
		currentInfo.FieldPaths = []string{}
		a.resetPaths()
		a.walk(op.SelectionSet, "", 0, currentInfo)

		// Count fragment definition directives (for inline + named fragments,
		// directives are counted inside walk; here we count directives
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

// maxFragmentDepth bounds how deep a fragment-reference chain may nest. Cycles
// are cut by the active-spread stack; this additionally stops pathological
// non-cyclic chains from exhausting the goroutine stack.
const maxFragmentDepth = 128

// fragStats holds the metrics contributed by one named fragment, measured
// relative to its spread point (depth 0, empty prefix) so they can be replayed
// unchanged at any nesting level.
type fragStats struct {
	maxRelDepth int
	fieldCount  int
	directives  int
	spreads     int
	inlineTypes int
	lists       int
	argDepth    int
	paths       []string
}

// analyzer walks a parsed document accumulating QueryInfo metrics. Fragment
// metrics are memoised (measured once, replayed per spread) and field paths are
// deduplicated, so replaying a fragment cannot amplify the path list.
type analyzer struct {
	doc   *ast.QueryDocument
	stack map[string]bool
	memo  map[string]*fragStats
	seen  map[string]bool
}

func newAnalyzer(doc *ast.QueryDocument) *analyzer {
	return &analyzer{
		doc:   doc,
		stack: make(map[string]bool),
		memo:  make(map[string]*fragStats),
		seen:  make(map[string]bool),
	}
}

// resetPaths starts a fresh path set for a new operation.
func (a *analyzer) resetPaths() {
	a.seen = make(map[string]bool)
}

// addPath records a field path once (set semantics).
func (a *analyzer) addPath(info *QueryInfo, path string) {
	if a.seen[path] {
		return
	}
	a.seen[path] = true
	info.FieldPaths = append(info.FieldPaths, path)
}

func (a *analyzer) walk(selections ast.SelectionSet, prefix string, depth int, info *QueryInfo) {
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
			a.addPath(info, path)

			newDepth := depth + 1
			if newDepth > info.Depth {
				info.Depth = newDepth
			}

			if s.SelectionSet != nil {
				a.walk(s.SelectionSet, path, newDepth, info)
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
				a.walk(s.SelectionSet, prefix, depth, info)
			}

		case *ast.FragmentSpread:
			info.FragmentSpreadCount++

			// Count directives on this fragment spread
			info.Directives += len(s.Directives)

			// Circular fragment references are cut by the active-spread stack;
			// non-circular references are replayed at every nesting level so a
			// deeper spread still contributes its full depth.
			if a.stack[s.Name] {
				continue
			}
			stats := a.memo[s.Name]
			if stats == nil {
				stats = a.measure(s.Name)
				if stats == nil {
					continue
				}
				a.memo[s.Name] = stats
			}
			a.applyFragmentStats(stats, prefix, depth, info)
		}
	}
}

// measure analyses a named fragment once, in isolation (depth 0, no prefix),
// and records the result for replay at each spread site.
func (a *analyzer) measure(name string) *fragStats {
	fragment := a.doc.Fragments.ForName(name)
	if fragment == nil || fragment.SelectionSet == nil {
		return nil
	}
	if len(a.stack) >= maxFragmentDepth {
		// Refuse to descend further; the fragment contributes nothing.
		return &fragStats{}
	}

	a.stack[name] = true
	defer delete(a.stack, name)

	// Private dedupe set: the fragment's paths are relative to its spread point.
	saved := a.seen
	a.seen = make(map[string]bool)
	defer func() { a.seen = saved }()

	tmp := &QueryInfo{FieldPaths: []string{}}
	a.walk(fragment.SelectionSet, "", 0, tmp)

	return &fragStats{
		maxRelDepth: tmp.Depth,
		fieldCount:  tmp.FieldCount,
		directives:  tmp.Directives,
		spreads:     tmp.FragmentSpreadCount,
		inlineTypes: tmp.InlineFragmentTypesCount,
		lists:       tmp.ListsRequested,
		argDepth:    tmp.ArgumentDepth,
		paths:       tmp.FieldPaths,
	}
}

// applyFragmentStats replays a fragment's relative metrics at a spread site.
func (a *analyzer) applyFragmentStats(st *fragStats, prefix string, depth int, info *QueryInfo) {
	if d := depth + st.maxRelDepth; d > info.Depth {
		info.Depth = d
	}
	info.FieldCount += st.fieldCount
	info.Directives += st.directives
	info.FragmentSpreadCount += st.spreads
	info.InlineFragmentTypesCount += st.inlineTypes
	info.ListsRequested += st.lists
	if st.argDepth > info.ArgumentDepth {
		info.ArgumentDepth = st.argDepth
	}
	for _, p := range st.paths {
		if prefix != "" {
			p = prefix + "." + p
		}
		a.addPath(info, p)
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
