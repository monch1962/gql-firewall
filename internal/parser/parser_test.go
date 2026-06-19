package parser

import (
	"testing"
)

func TestParseQuery_SimpleQuery(t *testing.T) {
	q := `{ user(id: 1) { name email } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.OperationType != "query" {
		t.Errorf("expected operation type 'query', got %q", info.OperationType)
	}
	if info.Depth != 2 {
		t.Errorf("expected depth 2, got %d", info.Depth)
	}
	// FieldCount includes all fields (intermediate + leaf): user, name, email
	if info.FieldCount != 3 {
		t.Errorf("expected 3 fields (user + name + email), got %d", info.FieldCount)
	}
}

func TestParseQuery_NamedQuery(t *testing.T) {
	q := `query GetUser { user(id: 1) { name email } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.OperationName != "GetUser" {
		t.Errorf("expected operation name 'GetUser', got %q", info.OperationName)
	}
	if info.OperationType != "query" {
		t.Errorf("expected operation type 'query', got %q", info.OperationType)
	}
}

func TestParseQuery_DeepNesting(t *testing.T) {
	q := `query { articles { comments { author { profile { avatar } } } } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Depth != 5 {
		t.Errorf("expected depth 5, got %d", info.Depth)
	}
	// articles, comments, author, profile, avatar = 5
	if info.FieldCount != 5 {
		t.Errorf("expected 5 fields, got %d", info.FieldCount)
	}
}

func TestParseQuery_Mutation(t *testing.T) {
	q := `mutation CreateUser($name: String!) { createUser(name: $name) { id name } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.OperationType != "mutation" {
		t.Errorf("expected operation type 'mutation', got %q", info.OperationType)
	}
}

func TestParseQuery_InvalidQuery(t *testing.T) {
	q := `{ user(id: 1) { name email `
	_, err := Parse(q)
	if err == nil {
		t.Fatal("expected error for invalid query, got nil")
	}
}

func TestParseQuery_EmptyQuery(t *testing.T) {
	_, err := Parse("")
	if err == nil {
		t.Fatal("expected error for empty query, got nil")
	}
}

func TestParseQuery_DepthWithFragments(t *testing.T) {
	q := `query { user { ...UserFields } } fragment UserFields on User { posts { title } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// user → posts → title = depth 3
	if info.Depth != 3 {
		t.Errorf("expected depth 3 (including fragment expansion), got %d", info.Depth)
	}
	// user, posts, title = 3 fields
	if info.FieldCount != 3 {
		t.Errorf("expected 3 fields (user + posts + title), got %d", info.FieldCount)
	}
}

func TestParseQuery_AliasedFields(t *testing.T) {
	q := `query { first: user(id: 1) { name } second: user(id: 2) { name } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Depth != 2 {
		t.Errorf("expected depth 2 (user → name), got %d", info.Depth)
	}
	// first, name, second, name = 4 fields (2 root aliases, each with name)
	if info.FieldCount != 4 {
		t.Errorf("expected 4 fields, got %d", info.FieldCount)
	}
}

func TestParseQuery_IntrospectionQuery(t *testing.T) {
	q := `query Introspection { __schema { types { name } } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// __schema → types → name = depth 3
	if info.Depth != 3 {
		t.Errorf("expected depth 3 for introspection, got %d", info.Depth)
	}
	// __schema, types, name = 3
	if info.FieldCount != 3 {
		t.Errorf("expected 3 fields, got %d", info.FieldCount)
	}
}

func TestParseQuery_ScalarQuery(t *testing.T) {
	q := `{ hello }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Depth != 1 {
		t.Errorf("expected depth 1, got %d", info.Depth)
	}
	if info.FieldCount != 1 {
		t.Errorf("expected 1 field, got %d", info.FieldCount)
	}
}

func TestParseQuery_Subscription(t *testing.T) {
	q := `subscription OnMessage { messageAdded { id content } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.OperationType != "subscription" {
		t.Errorf("expected operation type 'subscription', got %q", info.OperationType)
	}
}

func TestParseQuery_MultipleOperations(t *testing.T) {
	q := `query GetUser { user(id: 1) { name } } query GetPosts { posts { title } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should parse the first operation by default
	if info.OperationName != "GetUser" {
		t.Errorf("expected first operation 'GetUser', got %q", info.OperationName)
	}
}

func TestParseQuery_FieldPathExtraction(t *testing.T) {
	q := `query { user(id: 1) { profile { email age } } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(info.FieldPaths) == 0 {
		t.Fatal("expected field paths to be extracted")
	}
	// Paths include all nodes: user, user.profile, user.profile.email, user.profile.age
	expectedPaths := []string{"user", "user.profile", "user.profile.email", "user.profile.age"}
	if len(info.FieldPaths) != len(expectedPaths) {
		t.Fatalf("expected %d paths, got %d: %v", len(expectedPaths), len(info.FieldPaths), info.FieldPaths)
	}
	for i, path := range expectedPaths {
		if info.FieldPaths[i] != path {
			t.Errorf("expected path[%d] = %q, got %q", i, path, info.FieldPaths[i])
		}
	}
}

func TestParseQuery_FieldPathsWithFragments(t *testing.T) {
	q := `query { user { ...F } } fragment F on User { name email }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedPaths := []string{"user", "user.name", "user.email"}
	if len(info.FieldPaths) != len(expectedPaths) {
		t.Fatalf("expected %d paths, got %d: %v", len(expectedPaths), len(info.FieldPaths), info.FieldPaths)
	}
	for i, path := range expectedPaths {
		if info.FieldPaths[i] != path {
			t.Errorf("expected path[%d] = %q, got %q", i, path, info.FieldPaths[i])
		}
	}
}

func TestParseQuery_DepthLimitExample(t *testing.T) {
	// A practical depth-limited query — realistic for a GraphQL API
	q := `query Dashboard { me { organizations { repositories { issues { labels { name } } } } } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// me → orgs → repos → issues → labels → name = depth 6
	if info.Depth != 6 {
		t.Errorf("expected depth 6, got %d", info.Depth)
	}
	if info.FieldCount != 6 {
		t.Errorf("expected 6 fields, got %d", info.FieldCount)
	}
}

func TestParseQuery_CostEstimation(t *testing.T) {
	// A query with multiple fields at the same level — tests cost counting
	// Fields: users, id, name, email, avatar, url = 6 total at depth 3
	q := `query { users { id name email avatar { url } } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.FieldCount != 6 {
		t.Errorf("expected 6 fields (users + id + name + email + avatar + url), got %d", info.FieldCount)
	}
	if len(info.FieldPaths) != 6 {
		t.Fatalf("expected 6 paths, got %d", len(info.FieldPaths))
	}
}
