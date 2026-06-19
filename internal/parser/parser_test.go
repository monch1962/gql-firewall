package parser

import (
	"strings"
	"testing"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
	"github.com/vektah/gqlparser/v2/validator"
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
	// Should parse the first operation for type/name
	if info.OperationName != "GetUser" {
		t.Errorf("expected first operation 'GetUser', got %q", info.OperationName)
	}
	if info.OperationType != "query" {
		t.Errorf("expected operation type 'query', got %q", info.OperationType)
	}
	// Depth: user → name = 2, posts → title = 2, max = 2
	if info.Depth != 2 {
		t.Errorf("expected depth 2 (max across both ops), got %d", info.Depth)
	}
	// FieldCount: first op has 2 fields (user, name), second has 2 (posts, title), max = 2
	if info.FieldCount != 2 {
		t.Errorf("expected max field count 2, got %d", info.FieldCount)
	}
	// FieldPaths should include paths from BOTH operations
	expectedPaths := []string{"user", "user.name", "posts", "posts.title"}
	if len(info.FieldPaths) != len(expectedPaths) {
		t.Fatalf("expected %d paths from both operations, got %d: %v", len(expectedPaths), len(info.FieldPaths), info.FieldPaths)
	}
	for i, path := range expectedPaths {
		if info.FieldPaths[i] != path {
			t.Errorf("expected path[%d] = %q, got %q", i, path, info.FieldPaths[i])
		}
	}
}

func TestParseQuery_BatchOperations_MixedTypesAndDepths(t *testing.T) {
	// Batch query with 3 operations of varying complexity: one query deep, one shallow, one mutation
	q := `query GetDeep { users { posts { comments { author { name } } } } }
query GetShallow { health }
mutation CreatePost($title: String!) { createPost(title: $title) { id title } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Operation type/name from first operation
	if info.OperationName != "GetDeep" {
		t.Errorf("expected first operation 'GetDeep', got %q", info.OperationName)
	}
	if info.OperationType != "query" {
		t.Errorf("expected operation type 'query', got %q", info.OperationType)
	}
	// Depth: op1=5 (users→posts→comments→author→name), op2=1 (health), op3=2 (createPost→id/title)
	// Max = 5
	if info.Depth != 5 {
		t.Errorf("expected max depth 5, got %d", info.Depth)
	}
	// FieldCount per op: op1=5 fields, op2=1, op3=3. Max = 5
	if info.FieldCount != 5 {
		t.Errorf("expected max field count 5, got %d", info.FieldCount)
	}
	// All paths from all operations should be present
	expectedPaths := []string{
		"users",
		"users.posts",
		"users.posts.comments",
		"users.posts.comments.author",
		"users.posts.comments.author.name",
		"health",
		"createPost",
		"createPost.id",
		"createPost.title",
	}
	if len(info.FieldPaths) != len(expectedPaths) {
		t.Fatalf("expected %d paths from all operations, got %d: %v", len(expectedPaths), len(info.FieldPaths), info.FieldPaths)
	}
	for i, path := range expectedPaths {
		if info.FieldPaths[i] != path {
			t.Errorf("expected path[%d] = %q, got %q", i, path, info.FieldPaths[i])
		}
	}
}

func TestParseQuery_BatchOperations_AllQueries(t *testing.T) {
	// Batch of two same-depth queries — verifies max picks correctly
	q := `query A { user { name } } query B { users { name email } }`
	info, err := Parse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Depth = 2 for both, max = 2
	if info.Depth != 2 {
		t.Errorf("expected depth 2, got %d", info.Depth)
	}
	// FieldCount: opA=2 (user,name), opB=3 (users,name,email), max = 3
	if info.FieldCount != 3 {
		t.Errorf("expected max field count 3, got %d", info.FieldCount)
	}
	expectedPaths := []string{"user", "user.name", "users", "users.name", "users.email"}
	if len(info.FieldPaths) != len(expectedPaths) {
		t.Fatalf("expected %d paths, got %d: %v", len(expectedPaths), len(info.FieldPaths), info.FieldPaths)
	}
	for i, path := range expectedPaths {
		if info.FieldPaths[i] != path {
			t.Errorf("expected path[%d] = %q, got %q", i, path, info.FieldPaths[i])
		}
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

// buildTestSchema compiles an SDL string into a *SchemaInfo for use in tests.
func buildTestSchema(sdl string) *SchemaInfo {
	source := &ast.Source{Input: sdl, Name: "test"}
	doc, err := parser.ParseSchema(source)
	if err != nil {
		panic("invalid test schema: " + err.Error())
	}
	s, err := validator.ValidateSchemaDocument(doc)
	if err != nil {
		panic("invalid test schema: " + err.Error())
	}
	return &SchemaInfo{Schema: s, TypeCount: len(s.Types)}
}

func TestValidate_NestedPathValidation(t *testing.T) {
	schemaSDL := `
		scalar String
		scalar Int
		type Query {
			user: User
		}
		type User {
			name: String
			profile: Profile
		}
		type Profile {
			email: String
			age: Int
		}
	`
	schemaInfo := buildTestSchema(schemaSDL)

	tests := []struct {
		name    string
		paths   []string
		wantOK  bool
		wantMsg string
	}{
		{"top-level field exists", []string{"user"}, true, ""},
		{"single nested field", []string{"user.name"}, true, ""},
		{"deeply nested field", []string{"user.profile.email"}, true, ""},
		{"another deep nested field", []string{"user.profile.age"}, true, ""},
		{"invalid top-level field", []string{"nonexistent"}, false, `"nonexistent" does not exist on Query type`},
		{"invalid nested field", []string{"user.nonexistent"}, false, `"nonexistent" does not exist on type "User"`},
		{"invalid deeply nested field", []string{"user.profile.nonexistent"}, false, `"nonexistent" does not exist on type "Profile"`},
		{"multiple paths, one invalid", []string{"user", "user.nonexistent"}, false, `"nonexistent" does not exist on type "User"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &QueryInfo{FieldPaths: tt.paths}
			ok, msg := schemaInfo.Validate(info)
			if ok != tt.wantOK {
				t.Errorf("Validate() ok = %v, want %v; msg=%q", ok, tt.wantOK, msg)
			}
			if tt.wantMsg != "" && !strings.Contains(msg, tt.wantMsg) {
				t.Errorf("Validate() msg = %q, want it to contain %q", msg, tt.wantMsg)
			}
			if tt.wantMsg == "" && msg != "" {
				t.Errorf("Validate() msg = %q, want empty", msg)
			}
		})
	}
}

func TestValidate_AllPathsValid(t *testing.T) {
	schemaSDL := `
		scalar String
		type Query {
			user: User
			post: Post
		}
		type User {
			name: String
			profile: Profile
		}
		type Profile {
			email: String
		}
		type Post {
			title: String
			author: User
		}
	`
	schemaInfo := buildTestSchema(schemaSDL)

	info := &QueryInfo{
		FieldPaths: []string{
			"user",
			"user.name",
			"user.profile",
			"user.profile.email",
			"post",
			"post.title",
			"post.author",
			"post.author.name",
		},
	}

	ok, msg := schemaInfo.Validate(info)
	if !ok {
		t.Errorf("Validate() = false, want true; msg=%q", msg)
	}
}

func TestValidate_EmptyFieldPaths(t *testing.T) {
	schemaSDL := `scalar String
		type Query { hello: String }`
	schemaInfo := buildTestSchema(schemaSDL)

	info := &QueryInfo{FieldPaths: []string{}}
	ok, msg := schemaInfo.Validate(info)
	if !ok {
		t.Errorf("Validate() = false, want true (empty paths should pass); msg=%q", msg)
	}
}

func TestValidate_NilQueryType(t *testing.T) {
	// When Schema.Query is nil, Validate should return true (skip)
	schemaInfo := &SchemaInfo{Schema: &ast.Schema{}}
	info := &QueryInfo{FieldPaths: []string{"anything"}}
	ok, msg := schemaInfo.Validate(info)
	if !ok {
		t.Errorf("Validate() = false, want true when Query is nil; msg=%q", msg)
	}
}
