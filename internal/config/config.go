// Package config loads and watches GraphQL firewall configuration from JSON files.
// The configuration struct is shared with the rules package.
package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/monch1962/gql-firewall/internal/rules"
)

// Load reads a JSON configuration file and returns the parsed rules.
func Load(path string) (*rules.Config, error) {
	if path == "" {
		return nil, fmt.Errorf("config path is empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg rules.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config JSON: %w", err)
	}

	return &cfg, nil
}
