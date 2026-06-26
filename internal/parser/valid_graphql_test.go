package parser

import (
	"testing"
)

// ── Variable Definitions ──────────────────────────────────────────

func TestParseQuery_VariableCount(t *testing.T) {
	q := `query($id: ID!) { user(id: $id) { name } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.VariableCount != 1 {
		t.Errorf("expected variable_count=1, got %d", info.VariableCount)
	}
}

func TestParseQuery_MultipleVariables(t *testing.T) {
	q := `query($id: ID!, $limit: Int, $offset: Int) { users(id: $id, limit: $limit, offset: $offset) { name } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.VariableCount != 3 {
		t.Errorf("expected variable_count=3, got %d", info.VariableCount)
	}
}

func TestParseQuery_NoVariables(t *testing.T) {
	q := `{ hello }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.VariableCount != 0 {
		t.Errorf("expected variable_count=0, got %d", info.VariableCount)
	}
}

func TestParseQuery_VariableDefaultPresent(t *testing.T) {
	q := `query($limit: Int = 10) { users(limit: $limit) { name } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.HasDefaultVariables {
		t.Error("expected has_default_variables=true, got false")
	}
}

func TestParseQuery_VariableDefaultAbsent(t *testing.T) {
	q := `query($id: ID!) { user(id: $id) { name } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.HasDefaultVariables {
		t.Error("expected has_default_variables=false, got true")
	}
}

func TestParseQuery_VariableWithListType(t *testing.T) {
	q := `query($ids: [ID!]!) { users(ids: $ids) { name } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.VariableCount != 1 {
		t.Errorf("expected variable_count=1, got %d", info.VariableCount)
	}
}

func TestParseQuery_VariableDefaultComplex(t *testing.T) {
	q := `query($filter: FilterInput = {status: ACTIVE, limit: 10}) { items(filter: $filter) { id } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.HasDefaultVariables {
		t.Error("expected has_default_variables=true for default object value")
	}
}

// ── Operation-Level Directives ─────────────────────────────────────

func TestParseQuery_OperationDirectivesCounted(t *testing.T) {
	q := `query @deprecated { hello }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.OperationDirectives != 1 {
		t.Errorf("expected operation_directives=1, got %d", info.OperationDirectives)
	}
}

func TestParseQuery_MultipleOperationDirectives(t *testing.T) {
	q := `query @skip(if: false) @deprecated(reason: "test") { hello }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.OperationDirectives != 2 {
		t.Errorf("expected operation_directives=2, got %d", info.OperationDirectives)
	}
}

func TestParseQuery_NoOperationDirectives(t *testing.T) {
	q := `{ hello }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.OperationDirectives != 0 {
		t.Errorf("expected operation_directives=0, got %d", info.OperationDirectives)
	}
}

func TestParseQuery_MutationDirectives(t *testing.T) {
	q := `mutation @deprecated { createUser(name: "x") { id } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.OperationDirectives != 1 {
		t.Errorf("expected operation_directives=1, got %d", info.OperationDirectives)
	}
	if info.OperationType != "mutation" {
		t.Errorf("expected operation_type=mutation, got %q", info.OperationType)
	}
}

// ── Fragment Definition Directives ─────────────────────────────────

func TestParseQuery_FragmentDirectivesCounted(t *testing.T) {
	q := `query { ...F } fragment F on Query @deprecated { hello }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 1 directive on the fragment definition 'F'
	if info.Directives < 1 {
		t.Errorf("expected directives >= 1 (fragment def directive), got %d", info.Directives)
	}
}

func TestParseQuery_FragmentCount(t *testing.T) {
	q := `query { ...A ...B } fragment A on Query { x } fragment B on Query { y }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.FragmentCount != 2 {
		t.Errorf("expected fragment_count=2, got %d", info.FragmentCount)
	}
}

func TestParseQuery_NoFragments(t *testing.T) {
	q := `{ hello }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.FragmentCount != 0 {
		t.Errorf("expected fragment_count=0, got %d", info.FragmentCount)
	}
}

// ── Inline Fragment Type Conditions ─────────────────────────────────

func TestParseQuery_InlineFragmentTypeConditions(t *testing.T) {
	q := `{ users { ... on User { name } ... on Admin { role } } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.InlineFragmentTypesCount < 2 {
		t.Errorf("expected inline_fragment_types_count >= 2, got %d", info.InlineFragmentTypesCount)
	}
}

func TestParseQuery_NoInlineFragments(t *testing.T) {
	q := `{ user { name } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.InlineFragmentTypesCount != 0 {
		t.Errorf("expected inline_fragment_types_count=0, got %d", info.InlineFragmentTypesCount)
	}
}

func TestParseQuery_InlineFragmentDirectives(t *testing.T) {
	q := `{ users { ... @skip(if: true) { name } } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have counted the directive on the inline fragment
	if info.Directives < 1 {
		t.Errorf("expected directives >= 1 (inline frag directive), got %d", info.Directives)
	}
}

// ── Argument Value Types ───────────────────────────────────────────

func TestParseQuery_BooleanArgument(t *testing.T) {
	q := `{ user(active: true) { name } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.FieldCount == 0 {
		t.Error("expected fields to be parsed")
	}
}

func TestParseQuery_NullArgument(t *testing.T) {
	q := `{ user(name: null) { id } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.FieldCount == 0 {
		t.Error("expected fields to be parsed")
	}
}

func TestParseQuery_EnumArgument(t *testing.T) {
	q := `{ users(status: ACTIVE) { name } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.FieldCount == 0 {
		t.Error("expected fields to be parsed")
	}
}

func TestParseQuery_ListArgument(t *testing.T) {
	q := `{ users(ids: [1, 2, 3]) { name } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ArgumentDepth < 1 {
		t.Errorf("expected argument_depth >= 1 for list arg, got %d", info.ArgumentDepth)
	}
}

func TestParseQuery_NestedListArgument(t *testing.T) {
	q := `{ matrix(data: [[1, 2], [3, 4]]) { rows } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ArgumentDepth < 2 {
		t.Errorf("expected argument_depth >= 2 for nested list, got %d", info.ArgumentDepth)
	}
}

func TestParseQuery_DeepObjectArgument(t *testing.T) {
	q := `{ users(filter: {age: {gt: 18, lt: 99}, name: {eq: "Alice"}}) { name } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ArgumentDepth < 2 {
		t.Errorf("expected argument_depth >= 2 for nested object arg, got %d", info.ArgumentDepth)
	}
}

func TestParseQuery_MixedArgumentTypes(t *testing.T) {
	q := `{ search(input: {query: "test", filters: [{field: "status", value: ACTIVE}], limit: 10, offset: 0}) { id } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ArgumentDepth < 2 {
		t.Errorf("expected argument_depth >= 2 for mixed nested args, got %d", info.ArgumentDepth)
	}
	if info.FieldCount == 0 {
		t.Error("expected fields to be parsed")
	}
}

func TestParseQuery_IntegerArgument(t *testing.T) {
	q := `{ user(id: 42) { name } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.FieldCount == 0 {
		t.Error("expected fields to be parsed")
	}
}

func TestParseQuery_FloatArgument(t *testing.T) {
	q := `{ item(price: 19.99) { name } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.FieldCount == 0 {
		t.Error("expected fields to be parsed")
	}
}

func TestParseQuery_StringArgument(t *testing.T) {
	q := `{ user(name: "Alice") { id } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.FieldCount == 0 {
		t.Error("expected fields to be parsed")
	}
}

func TestParseQuery_VariableArgument(t *testing.T) {
	q := `query($id: ID!) { user(id: $id) { name } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ArgumentDepth < 1 {
		t.Errorf("expected argument_depth >= 1 for variable arg ref, got %d", info.ArgumentDepth)
	}
}

// ── Multi-Operation Variables ──────────────────────────────────────

func TestParseQuery_MultiOpWithVariables(t *testing.T) {
	q := `query GetUser($id: ID!) { user(id: $id) { name } } query GetPosts($limit: Int = 10) { posts(limit: $limit) { title } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should capture max variable count across ops (whichever is larger)
	if info.VariableCount < 1 {
		t.Errorf("expected variable_count >= 1 across operations, got %d", info.VariableCount)
	}
	// At least one op has default variables
	if !info.HasDefaultVariables {
		t.Error("expected has_default_variables=true (GetPosts has default limit=10)")
	}
}

// ── Meta Fields ────────────────────────────────────────────────────

func TestParseQuery_TypenameMetaField(t *testing.T) {
	q := `{ __typename }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.FieldCount != 1 {
		t.Errorf("expected 1 field (__typename), got %d", info.FieldCount)
	}
}

func TestParseQuery_TypenameOnNested(t *testing.T) {
	q := `{ users { __typename name } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.FieldCount != 3 {
		t.Errorf("expected 3 fields (users, __typename, name), got %d", info.FieldCount)
	}
}

// ── Comment in Query ───────────────────────────────────────────────

func TestParseQuery_WithComment(t *testing.T) {
	q := `{ # fetch the user
		user(id: 1) { name } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error for query with comment: %v", err)
	}
	if info.FieldCount != 2 {
		t.Errorf("expected 2 fields (user, name), got %d", info.FieldCount)
	}
}

// ── Mutation with Input Object ─────────────────────────────────────

func TestParseQuery_MutationWithInputObject(t *testing.T) {
	q := `mutation($input: CreateUserInput!) { createUser(input: $input) { id name email } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.OperationType != "mutation" {
		t.Errorf("expected mutation type, got %q", info.OperationType)
	}
	if info.VariableCount != 1 {
		t.Errorf("expected variable_count=1, got %d", info.VariableCount)
	}
	if info.FieldCount != 4 {
		t.Errorf("expected 4 fields (createUser, id, name, email), got %d", info.FieldCount)
	}
}

// ── Subscription ──────────────────────────────────────────────────

func TestParseQuery_SubscriptionWithVariables(t *testing.T) {
	q := `subscription($roomId: ID!) { messageAdded(roomId: $roomId) { id text } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.OperationType != "subscription" {
		t.Errorf("expected operation_type=subscription, got %q", info.OperationType)
	}
	if info.VariableCount != 1 {
		t.Errorf("expected variable_count=1, got %d", info.VariableCount)
	}
}

// ── Nested Fragment Spreads ────────────────────────────────────────

func TestParseQuery_NestedNamedFragments(t *testing.T) {
	q := `query { user { ...UserFields } }
		fragment UserFields on User { profile { ...ProfileFields } }
		fragment ProfileFields on Profile { email avatar }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.FragmentCount != 2 {
		t.Errorf("expected fragment_count=2, got %d", info.FragmentCount)
	}
	// user → profile → email/avatar = depth 3
	if info.Depth != 3 {
		t.Errorf("expected depth 3 with nested fragments, got %d", info.Depth)
	}
}

// ── Deep Argument Depth ────────────────────────────────────────────

func TestParseQuery_VeryDeepArgumentDepth(t *testing.T) {
	q := `{ search(filter: {a: {b: {c: {d: {e: "deep"}}}}}) { result } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ArgumentDepth < 4 {
		t.Errorf("expected argument_depth >= 4 for deeply nested object, got %d", info.ArgumentDepth)
	}
}

// ── Combined: All Features ─────────────────────────────────────────

func TestParseQuery_AllFeaturesCombined(t *testing.T) {
	q := `query GetData($id: ID!, $limit: Int = 20) @deprecated {
		user(id: $id) {
			... on User {
				id
				name
				posts(filter: {published: true, tags: ["graphql"]}, limit: $limit) {
					title
					...PostFields
				}
			}
		}
	}
	fragment PostFields on Post @deprecated {
		title
		comments { id body }
	}`

	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Operation name
	if info.OperationName != "GetData" {
		t.Errorf("expected operation_name=GetData, got %q", info.OperationName)
	}

	// Operation type
	if info.OperationType != "query" {
		t.Errorf("expected operation_type=query, got %q", info.OperationType)
	}

	// Variables: $id (no default), $limit (default=20)
	if info.VariableCount != 2 {
		t.Errorf("expected variable_count=2, got %d", info.VariableCount)
	}
	if !info.HasDefaultVariables {
		t.Error("expected has_default_variables=true ($limit has default)")
	}

	// Operation directive: @deprecated
	if info.OperationDirectives != 1 {
		t.Errorf("expected operation_directives=1, got %d", info.OperationDirectives)
	}

	// Fragment definition directives: PostFields has @deprecated
	if info.Directives < 1 {
		t.Errorf("expected directives >= 1 (includes @deprecated on PostFields), got %d", info.Directives)
	}

	// Fragment count: PostFields
	if info.FragmentCount != 1 {
		t.Errorf("expected fragment_count=1, got %d", info.FragmentCount)
	}

	// Inline fragment: ... on User
	if info.InlineFragmentTypesCount < 1 {
		t.Errorf("expected inline_fragment_types_count >= 1, got %d", info.InlineFragmentTypesCount)
	}

	// Argument depth: filter: {published: true, tags: [...]} has depth 2
	if info.ArgumentDepth < 2 {
		t.Errorf("expected argument_depth >= 2 (nested filter object), got %d", info.ArgumentDepth)
	}

	// Depth: user → ...on User → ... → posts → ...PostFields → ... → comments → body = depth 4+
	if info.Depth < 4 {
		t.Errorf("expected depth >= 4, got %d", info.Depth)
	}

	// Lists heuristic: posts ends in 's', comments ends in 's'
	if info.ListsRequested < 2 {
		t.Errorf("expected lists_requested >= 2 (posts, comments), got %d", info.ListsRequested)
	}

	// Batch size
	if info.BatchSize != 1 {
		t.Errorf("expected batch_size=1, got %d", info.BatchSize)
	}

	// Query hash
	if info.QueryHash == "" {
		t.Error("expected non-empty query_hash")
	}
}
