// Package config loads and watches GraphQL firewall configuration from JSON files.
// The configuration struct is shared with the rules package.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
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

// Watch monitors the config file for changes and sends updated configs
// on the returned channel. The first config is sent immediately on read.
// The channel is closed when the watcher encounters an unrecoverable error.
func Watch(path string) (<-chan *rules.Config, error) {
	if path == "" {
		return nil, fmt.Errorf("config path is empty")
	}

	// Initial load
	cfg, err := Load(path)
	if err != nil {
		return nil, fmt.Errorf("initial config load: %w", err)
	}

	ch := make(chan *rules.Config, 1)
	ch <- cfg

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("creating file watcher: %w", err)
	}

	dir := filepath.Dir(path)
	if err := watcher.Add(dir); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("watching config directory: %w", err)
	}

	go func() {
		defer watcher.Close()
		defer close(ch)

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Only reload on write events to the specific file
				if event.Op&(fsnotify.Write|fsnotify.Create) != 0 && event.Name == path {
					newCfg, err := Load(path)
					if err != nil {
						// Log and continue — don't close the channel on a transient error
						continue
					}
					ch <- newCfg
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				_ = err // Log in production; for now, carry on
			}
		}
	}()

	return ch, nil
}
