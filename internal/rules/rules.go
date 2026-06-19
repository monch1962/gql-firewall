// Package rules provides configurable rule evaluation for GraphQL queries.
// Rules are loaded from a JSON configuration and evaluated against
// parsed QueryInfo to determine if a query should be allowed or rejected.
package rules

import (
	"fmt"
	"strings"

	"github.com/monch1962/gql-firewall/internal/parser"
)

// Config holds all configurable rules for the GraphQL firewall.
type Config struct {
	// DepthLimit is the maximum allowed query nesting depth. 0 = disabled.
	DepthLimit int `json:"depth_limit,omitempty"`

	// MaxFieldCount is the maximum number of fields in a query. 0 = disabled.
	MaxFieldCount int `json:"max_field_count,omitempty"`

	// BlockedOperations is a list of operation types to block (e.g. "mutation").
	// If empty, all operations are allowed (unless restricted by AllowedOperations).
	BlockedOperations []string `json:"blocked_operations,omitempty"`

	// AllowedOperations is a list of operation types that are allowed.
	// If set, only these operations pass. If both Allowed and Blocked are set,
	// Blocked takes precedence.
	AllowedOperations []string `json:"allowed_operations,omitempty"`

	// FieldAllowlist is a list of field paths that are permitted.
	// If set, only these fields (or their ancestors) are allowed.
	// An empty list means no restriction.
	FieldAllowlist []string `json:"field_allowlist,omitempty"`

	// FieldBlocklist is a list of field paths that are denied.
	// Blocklist takes precedence over allowlist.
	FieldBlocklist []string `json:"field_blocklist,omitempty"`
}

// Result holds the outcome of rule evaluation.
type Result struct {
	// Allowed is true if the query passes all rules.
	Allowed bool `json:"allowed"`
	// Reason describes why the query was blocked (empty if allowed).
	Reason string `json:"reason,omitempty"`
}

// Evaluate checks a parsed query against all configured rules.
// Returns the first blocking result, or Allowed if all rules pass.
func (c *Config) Evaluate(info *parser.QueryInfo) *Result {
	if c == nil {
		return &Result{Allowed: true}
	}

	// 1. Operation type restrictions
	if len(c.BlockedOperations) > 0 {
		for _, blocked := range c.BlockedOperations {
			if strings.EqualFold(info.OperationType, blocked) {
				return &Result{
					Allowed: false,
					Reason:  fmt.Sprintf("operation type %q is blocked", info.OperationType),
				}
			}
		}
	}

	if len(c.AllowedOperations) > 0 {
		allowed := false
		for _, op := range c.AllowedOperations {
			if strings.EqualFold(info.OperationType, op) {
				allowed = true
				break
			}
		}
		if !allowed {
			return &Result{
				Allowed: false,
				Reason:  fmt.Sprintf("operation type %q is not in allowed list", info.OperationType),
			}
		}
	}

	// 2. Depth limit
	if c.DepthLimit > 0 && info.Depth > c.DepthLimit {
		return &Result{
			Allowed: false,
			Reason:  fmt.Sprintf("query depth %d exceeds limit of %d", info.Depth, c.DepthLimit),
		}
	}

	// 3. Field count limit
	if c.MaxFieldCount > 0 && info.FieldCount > c.MaxFieldCount {
		return &Result{
			Allowed: false,
			Reason:  fmt.Sprintf("field count %d exceeds limit of %d", info.FieldCount, c.MaxFieldCount),
		}
	}

	// 4. Field blocklist (checked before allowlist — blocklist takes precedence)
	if len(c.FieldBlocklist) > 0 {
		for _, path := range info.FieldPaths {
			for _, blocked := range c.FieldBlocklist {
				if path == blocked || strings.HasPrefix(path, blocked+".") {
					return &Result{
						Allowed: false,
						Reason:  fmt.Sprintf("field %q is blocked", path),
					}
				}
			}
		}
	}

	// 5. Field allowlist
	if len(c.FieldAllowlist) > 0 {
		for _, path := range info.FieldPaths {
			allowed := false
			for _, permitted := range c.FieldAllowlist {
				if path == permitted || strings.HasPrefix(permitted, path+".") {
					allowed = true
					break
				}
			}
			if !allowed {
				return &Result{
					Allowed: false,
					Reason:  fmt.Sprintf("field %q is not in allowlist", path),
				}
			}
		}
	}

	return &Result{Allowed: true}
}
