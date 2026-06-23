package opa

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SidecarClient communicates with an OPA sidecar via HTTP.
type SidecarClient struct {
	endpoint   string
	httpClient *http.Client
}

// NewSidecar creates an OPA sidecar client.
func NewSidecar(endpoint string) *SidecarClient {
	return &SidecarClient{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Configured returns true if an OPA endpoint was configured.
func (c *SidecarClient) Configured() bool {
	return c.endpoint != ""
}

// Evaluate sends query information to OPA and returns the decision.
func (c *SidecarClient) Evaluate(input *Input) (*Result, error) {
	if c.endpoint == "" {
		return &Result{Allowed: true}, nil
	}

	body, err := json.Marshal(map[string]interface{}{
		"input": input,
	})
	if err != nil {
		return nil, fmt.Errorf("marshalling OPA input: %w", err)
	}

	resp, err := c.httpClient.Post(c.endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("calling OPA: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OPA returned status %d", resp.StatusCode)
	}

	var opaResp struct {
		Result struct {
			Allowed bool   `json:"allowed"`
			Reason  string `json:"reason,omitempty"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return nil, fmt.Errorf("decoding OPA response: %w", err)
	}

	return &Result{
		Allowed: opaResp.Result.Allowed,
		Reason:  opaResp.Result.Reason,
	}, nil
}
