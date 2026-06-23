package opa

import (
	"context"
	"fmt"
	"sync"

	v1 "github.com/open-policy-agent/opa/v1/rego"
)

// EmbedConfig holds configuration for the embedded Rego evaluator.
type EmbedConfig struct {
	// Policy is the Rego source code to evaluate.
	Policy string
	// Store provides params and tenant data injected into the evaluation input.
	Store *DataStore
}

// EmbeddedEvaluator evaluates Rego policies in-process using the OPA Go library.
type EmbeddedEvaluator struct {
	mu        sync.RWMutex
	prepared  *v1.PreparedEvalQuery
	store     *DataStore
	policy    string
}

// NewEmbedded creates an embedded Rego evaluator.
func NewEmbedded(cfg EmbedConfig) (*EmbeddedEvaluator, error) {
	if cfg.Policy == "" {
		return nil, fmt.Errorf("OPA policy source is empty")
	}
	if cfg.Store == nil {
		cfg.Store = NewDataStore()
	}

	e := &EmbeddedEvaluator{
		store:  cfg.Store,
		policy: cfg.Policy,
	}

	if err := e.compile(); err != nil {
		return nil, fmt.Errorf("compiling embedded OPA policy: %w", err)
	}

	return e, nil
}

// Configured returns true — the embedded evaluator is always ready.
func (e *EmbeddedEvaluator) Configured() bool {
	return true
}

// Evaluate checks a query against the embedded Rego policy.
func (e *EmbeddedEvaluator) Evaluate(input *Input) (*Result, error) {
	e.mu.RLock()
	prepared := e.prepared
	e.mu.RUnlock()

	if prepared == nil {
		return nil, fmt.Errorf("embedded OPA evaluator not initialized")
	}

	ctx := context.Background()

	// Evaluate the allow query
	rs, err := prepared.Eval(ctx,
		v1.EvalInput(input),
	)
	if err != nil {
		return nil, fmt.Errorf("OPA evaluation error: %w", err)
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return &Result{Allowed: false, Reason: "OPA policy evaluation returned no result"}, nil
	}

	allowed, ok := rs[0].Expressions[0].Value.(bool)
	if !ok {
		return &Result{Allowed: false, Reason: "OPA policy returned non-boolean result"}, nil
	}

	if allowed {
		return &Result{Allowed: true}, nil
	}

	// Denied — extract reason from deny set
	denyRs, err := v1.New(
		v1.Query("data.graphql.deny"),
		v1.Module("graphql.rego", e.policy),
		v1.Input(input),
	).Eval(ctx)
	if err != nil {
		return &Result{Allowed: false, Reason: "blocked by OPA policy"}, nil
	}

	if len(denyRs) > 0 && len(denyRs[0].Expressions) > 0 {
		if denialSet, ok := denyRs[0].Expressions[0].Value.([]interface{}); ok && len(denialSet) > 0 {
			if reason, ok := denialSet[0].(string); ok {
				return &Result{Allowed: false, Reason: reason}, nil
			}
		}
	}

	return &Result{Allowed: false, Reason: "blocked by OPA policy"}, nil
}

// compile pre-compiles the Rego policy for faster evaluation.
func (e *EmbeddedEvaluator) compile() error {
	r := v1.New(
		v1.Query("data.graphql.allow"),
		v1.Module("graphql.rego", e.policy),
	)
	prepared, err := r.PrepareForEval(context.Background())
	if err != nil {
		return err
	}
	e.prepared = &prepared
	return nil
}

// SetParams updates the parameters in the data store.
func (e *EmbeddedEvaluator) SetParams(params map[string]interface{}) {
	e.store.SetParams(params)
}
