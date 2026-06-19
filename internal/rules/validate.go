package rules

import (
	"errors"
)

var (
	ErrNilConfig       = errors.New("config is nil")
	ErrNoProtection    = errors.New("config must have at least one protection enabled (depth_limit, max_field_count, or field_blocklist)")
	ErrNegativeDepth   = errors.New("depth_limit must be non-negative")
	ErrNegativeFields  = errors.New("max_field_count must be non-negative")
)

// Validate checks the config for safe, non-zero values.
// Returns an error if the config would effectively disable all protections.
func Validate(cfg *Config) error {
	if cfg == nil {
		return ErrNilConfig
	}
	if cfg.DepthLimit < 0 {
		return ErrNegativeDepth
	}
	if cfg.MaxFieldCount < 0 {
		return ErrNegativeFields
	}
	// Check at least one protection is enabled
	if cfg.DepthLimit == 0 && cfg.MaxFieldCount == 0 && len(cfg.FieldBlocklist) == 0 && len(cfg.FieldAllowlist) == 0 && len(cfg.AllowedOperations) == 0 && len(cfg.BlockedOperations) == 0 {
		return ErrNoProtection
	}
	return nil
}
