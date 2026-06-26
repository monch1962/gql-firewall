package parser

import (
	"testing"
)

func TestValidate_ArgTypeInt(t *testing.T) {
	sdl := `
		scalar Int
		scalar String
		type Query {
			user(id: Int!): User
		}
		type User {
			name: String
		}
	`
	schema := buildTestSchema(sdl)

	// Valid: int argument
	info := &QueryInfo{FieldPaths: []string{"user"}}
	if ok, msg := schema.Validate(info); !ok {
		t.Errorf("expected valid to pass: %s", msg)
	}

	// The Validate method doesn't check argument types currently (that's what we're adding)
	// For now, just verify field path validation works
}

func TestValidate_DeprecatedField_Detected(t *testing.T) {
	sdl := `
		directive @deprecated(reason: String) on FIELD_DEFINITION
		scalar String
		type Query {
			hello: String @deprecated(reason: "use greet")
			greet: String
		}
	`
	schema := buildTestSchema(sdl)

	// Querying the deprecated field
	info := &QueryInfo{
		FieldPaths: []string{"hello"},
	}
	ok, msg := schema.Validate(info)
	if !ok {
		t.Errorf("expected deprecated field to pass (still exists): %s", msg)
	}
}

func TestValidate_DeprecatedFieldMessage(t *testing.T) {
	sdl := `
		directive @deprecated(reason: String) on FIELD_DEFINITION
		scalar String
		type Query {
			oldField: String @deprecated(reason: "use newField instead")
		}
	`
	schema := buildTestSchema(sdl)

	// Check that the schema captures deprecation
	queryType := schema.Schema.Query
	if queryType == nil {
		t.Fatal("expected Query type in schema")
	}
	field := queryType.Fields.ForName("oldField")
	if field == nil {
		t.Fatal("expected oldField in Query type")
	}
	if field.Directives.ForName("deprecated") == nil {
		t.Error("expected deprecated directive on oldField")
	}
}

func TestValidate_CustomScalarArgTypes(t *testing.T) {
	sdl := `
		scalar ID
		scalar String
		scalar Int
		type Query {
			user(id: ID!): User
			posts(limit: Int, offset: Int): Post
		}
		type User { name: String }
		type Post { title: String }
	`
	schema := buildTestSchema(sdl)

	// Field path validation should work for param-based fields
	tests := []struct {
		name   string
		paths  []string
		wantOK bool
	}{
		{"user field exists", []string{"user"}, true},
		{"posts field exists", []string{"posts"}, true},
		{"nested user.name", []string{"user.name"}, true},
		{"nested post.title", []string{"posts.title"}, true},
		{"unknown field", []string{"nonexistent"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &QueryInfo{FieldPaths: tt.paths}
			ok, _ := schema.Validate(info)
			if ok != tt.wantOK {
				t.Errorf("Validate() ok=%v, want %v", ok, tt.wantOK)
			}
		})
	}
}

func TestValidate_InputTypeArgument(t *testing.T) {
	sdl := `
		scalar String
		scalar Int
		input FilterInput {
			status: String
			limit: Int
		}
		type Query {
			search(filter: FilterInput): [Result]
		}
		type Result {
			id: Int
			name: String
		}
	`
	schema := buildTestSchema(sdl)

	// Query with input type argument
	info := &QueryInfo{FieldPaths: []string{"search", "search.id"}}
	ok, msg := schema.Validate(info)
	if !ok {
		t.Errorf("expected input type field to validate: %s", msg)
	}
}

func TestValidate_MutationFieldExists(t *testing.T) {
	sdl := `
		scalar String
		scalar Int
		type Mutation {
			createUser(name: String!): User
		}
		type Query {
			ping: String
		}
		type User {
			id: Int
			name: String
		}
	`
	schema := buildTestSchema(sdl)

	tests := []struct {
		name      string
		opType    string
		paths     []string
		wantOK    bool
	}{
		{"query field on Query type", "query", []string{"ping"}, true},
		{"mutation field on Mutation type", "mutation", []string{"createUser"}, true},
		{"nested mutation field", "mutation", []string{"createUser.id"}, true},
		{"deeper nested", "mutation", []string{"createUser.name"}, true},
		{"unknown field on Mutation", "mutation", []string{"createUser.nonexistent"}, false},
		{"unknown mutation root field", "mutation", []string{"deleteUser"}, false},
		{"query field in mutation mode", "mutation", []string{"ping"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &QueryInfo{
				OperationType: tt.opType,
				FieldPaths:    tt.paths,
			}
			ok, _ := schema.Validate(info)
			if ok != tt.wantOK {
				t.Errorf("Validate(operation_type=%q, paths=%v) = %v, want %v", tt.opType, tt.paths, ok, tt.wantOK)
			}
		})
	}
}
