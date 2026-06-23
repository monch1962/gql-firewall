// Package opa provides OPA integration for the GraphQL firewall.
// Supports both HTTP sidecar mode (--opa) and embedded Rego evaluation (--opa-embed).
package opa

// Result holds the outcome of OPA policy evaluation.
type Result struct {
	// Allowed is true if the query passes all policies.
	Allowed bool `json:"allowed"`
	// Reason describes why the query was blocked (empty if allowed).
	Reason string `json:"reason,omitempty"`
}

// Evaluator is the interface for OPA policy evaluation.
type Evaluator interface {
	// Evaluate checks a parsed query against OPA policies.
	Evaluate(input *Input) (*Result, error)
	// Configured returns true if the evaluator is ready.
	Configured() bool
}
