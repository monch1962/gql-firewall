// Package opa provides integration with Open Policy Agent for external
// policy evaluation. When configured, every query is sent to OPA for
// decision-making. When OPA is not configured, the client returns
// allow-by-default.
package opa

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/monch1962/gql-firewall/internal/parser"
	"github.com/monch1962/gql-firewall/internal/rules"
)

// Client communicates with an OPA sidecar for policy evaluation.
type Client struct {
	endpoint   string
	httpClient *http.Client
}

// New creates an OPA client. If endpoint is empty, the client returns
// allow-by-default for all queries (OPA is optional).
func New(endpoint string) *Client {
	return &Client{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// opaInput is the JSON structure sent to OPA.
type opaInput struct {
	OperationType string   `json:"operation_type"`
	OperationName string   `json:"operation_name,omitempty"`
	Depth         int      `json:"depth"`
	FieldCount    int      `json:"field_count"`
	FieldPaths    []string `json:"field_paths,omitempty"`
}

// opaResponse is the JSON structure returned by OPA.
type opaResponse struct {
	Result struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason,omitempty"`
	} `json:"result"`
}

// Configured returns true if an OPA endpoint was configured.
func (c *Client) Configured() bool {
	return c.endpoint != ""
}

// Evaluate sends query information to OPA and returns the decision.
// Returns allow-by-default if OPA is not configured.
func (c *Client) Evaluate(info *parser.QueryInfo) (*rules.Result, error) {
	if c.endpoint == "" {
		// OPA is optional — allow by default when not configured
		return &rules.Result{Allowed: true}, nil
	}

	input := opaInput{
		OperationType: info.OperationType,
		OperationName: info.OperationName,
		Depth:         info.Depth,
		FieldCount:    info.FieldCount,
		FieldPaths:    info.FieldPaths,
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

	var opaResp opaResponse
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return nil, fmt.Errorf("decoding OPA response: %w", err)
	}

	return &rules.Result{
		Allowed: opaResp.Result.Allowed,
		Reason:  opaResp.Result.Reason,
	}, nil
}
