// Package rules provides configurable rule evaluation for GraphQL queries.
// Rules are loaded from a JSON configuration and evaluated against
// parsed QueryInfo to determine if a query should be allowed, rejected,
// or modified.
package rules

import (
	"testing"

	"github.com/monch1962/gql-firewall/internal/parser"
)

func TestDepthLimit_UnderLimit(t *testing.T) {
	rules := Config{
		DepthLimit: 5,
	}
	info := &parser.QueryInfo{Depth: 3}
	result := rules.Evaluate(info)
	if !result.Allowed {
		t.Errorf("expected query allowed (depth 3 ≤ 5), got blocked: %s", result.Reason)
	}
}

func TestDepthLimit_AtLimit(t *testing.T) {
	rules := Config{
		DepthLimit: 5,
	}
	info := &parser.QueryInfo{Depth: 5}
	result := rules.Evaluate(info)
	if !result.Allowed {
		t.Errorf("expected query allowed (depth 5 ≤ 5), got blocked: %s", result.Reason)
	}
}

func TestDepthLimit_OverLimit(t *testing.T) {
	rules := Config{
		DepthLimit: 3,
	}
	info := &parser.QueryInfo{Depth: 5}
	result := rules.Evaluate(info)
	if result.Allowed {
		t.Fatal("expected query blocked (depth 5 > 3), got allowed")
	}
	if result.Reason == "" {
		t.Error("expected non-empty reason for blocked query")
	}
}

func TestDepthLimit_Disabled(t *testing.T) {
	rules := Config{
		DepthLimit: 0, // 0 means disabled
	}
	info := &parser.QueryInfo{Depth: 100}
	result := rules.Evaluate(info)
	if !result.Allowed {
		t.Errorf("expected query allowed (depth limit disabled), got blocked: %s", result.Reason)
	}
}

func TestFieldCountLimit_UnderLimit(t *testing.T) {
	rules := Config{
		MaxFieldCount: 50,
	}
	info := &parser.QueryInfo{FieldCount: 10}
	result := rules.Evaluate(info)
	if !result.Allowed {
		t.Errorf("expected query allowed (10 ≤ 50), got blocked: %s", result.Reason)
	}
}

func TestFieldCountLimit_OverLimit(t *testing.T) {
	rules := Config{
		MaxFieldCount: 20,
	}
	info := &parser.QueryInfo{FieldCount: 100}
	result := rules.Evaluate(info)
	if result.Allowed {
		t.Fatal("expected query blocked (100 > 20), got allowed")
	}
	if result.Reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestFieldCountLimit_Disabled(t *testing.T) {
	rules := Config{}
	info := &parser.QueryInfo{FieldCount: 10000}
	result := rules.Evaluate(info)
	if !result.Allowed {
		t.Errorf("expected query allowed (field count limit disabled), got blocked: %s", result.Reason)
	}
}

func TestBlockedOperations_MutationBlocked(t *testing.T) {
	rules := Config{
		BlockedOperations: []string{"mutation"},
	}
	info := &parser.QueryInfo{OperationType: "mutation"}
	result := rules.Evaluate(info)
	if result.Allowed {
		t.Fatal("expected mutation blocked, got allowed")
	}
}

func TestBlockedOperations_QueryAllowed(t *testing.T) {
	rules := Config{
		BlockedOperations: []string{"mutation"},
	}
	info := &parser.QueryInfo{OperationType: "query"}
	result := rules.Evaluate(info)
	if !result.Allowed {
		t.Errorf("expected query allowed, got blocked: %s", result.Reason)
	}
}

func TestBlockedOperations_MultipleBlocked(t *testing.T) {
	rules := Config{
		BlockedOperations: []string{"mutation", "subscription"},
	}
	info := &parser.QueryInfo{OperationType: "subscription"}
	result := rules.Evaluate(info)
	if result.Allowed {
		t.Fatal("expected subscription blocked, got allowed")
	}
}

func TestAllowedOperations_MutationAllowed(t *testing.T) {
	rules := Config{
		AllowedOperations: []string{"query", "mutation"},
	}
	info := &parser.QueryInfo{OperationType: "mutation"}
	result := rules.Evaluate(info)
	if !result.Allowed {
		t.Errorf("expected mutation allowed, got blocked: %s", result.Reason)
	}
}

func TestAllowedOperations_SubscriptionDenied(t *testing.T) {
	rules := Config{
		AllowedOperations: []string{"query", "mutation"},
	}
	info := &parser.QueryInfo{OperationType: "subscription"}
	result := rules.Evaluate(info)
	if result.Allowed {
		t.Fatal("expected subscription blocked, got allowed")
	}
}

func TestFieldAllowlist_FieldAllowed(t *testing.T) {
	rules := Config{
		FieldAllowlist: []string{"user.name", "user.email", "posts.title"},
	}
	info := &parser.QueryInfo{
		FieldPaths: []string{"user", "user.name"},
	}
	result := rules.Evaluate(info)
	if !result.Allowed {
		t.Errorf("expected 'user.name' allowed, got blocked: %s", result.Reason)
	}
}

func TestFieldAllowlist_FieldBlocked(t *testing.T) {
	rules := Config{
		FieldAllowlist: []string{"user.name", "user.email"},
	}
	info := &parser.QueryInfo{
		FieldPaths: []string{"user", "user.ssn"},
	}
	result := rules.Evaluate(info)
	if result.Allowed {
		t.Fatal("expected 'user.ssn' blocked (not in allowlist), got allowed")
	}
}

func TestFieldBlocklist_FieldBlocked(t *testing.T) {
	rules := Config{
		FieldBlocklist: []string{"user.ssn", "user.password"},
	}
	info := &parser.QueryInfo{
		FieldPaths: []string{"user", "user.name", "user.ssn"},
	}
	result := rules.Evaluate(info)
	if result.Allowed {
		t.Fatal("expected 'user.ssn' blocked, got allowed")
	}
}

func TestFieldBlocklist_FieldAllowed(t *testing.T) {
	rules := Config{
		FieldBlocklist: []string{"user.ssn", "user.password"},
	}
	info := &parser.QueryInfo{
		FieldPaths: []string{"user", "user.name", "user.email"},
	}
	result := rules.Evaluate(info)
	if !result.Allowed {
		t.Errorf("expected allowed (no blocked fields), got blocked: %s", result.Reason)
	}
}

func TestMultipleRules_AllPass(t *testing.T) {
	rules := Config{
		DepthLimit:        5,
		MaxFieldCount:     20,
		AllowedOperations: []string{"query"},
	}
	info := &parser.QueryInfo{
		OperationType: "query",
		Depth:         3,
		FieldCount:    10,
	}
	result := rules.Evaluate(info)
	if !result.Allowed {
		t.Errorf("expected all rules pass, got blocked: %s", result.Reason)
	}
}

func TestMultipleRules_FirstFail(t *testing.T) {
	rules := Config{
		DepthLimit:        3,
		MaxFieldCount:     20,
		AllowedOperations: []string{"query"},
	}
	info := &parser.QueryInfo{
		OperationType: "query",
		Depth:         10,
		FieldCount:    5,
	}
	result := rules.Evaluate(info)
	if result.Allowed {
		t.Fatal("expected blocked (depth 10 > 3), got allowed")
	}
	// The first failing rule should report depth, not field count
	// (rules are evaluated depth-first in order of definition)
}

func TestNoRulesConfigured(t *testing.T) {
	rules := Config{}
	info := &parser.QueryInfo{
		OperationType: "mutation",
		Depth:         100,
		FieldCount:    500,
		FieldPaths:    []string{"admin", "admin.deleteAllUsers"},
	}
	result := rules.Evaluate(info)
	if !result.Allowed {
		t.Errorf("expected all allowed (no rules configured), got blocked: %s", result.Reason)
	}
}
