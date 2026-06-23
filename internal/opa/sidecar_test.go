package opa

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSidecar_Configured(t *testing.T) {
	c := NewSidecar("")
	if c.Configured() {
		t.Error("expected Configured()=false for empty endpoint")
	}
	c2 := NewSidecar("http://localhost:8181")
	if !c2.Configured() {
		t.Error("expected Configured()=true for non-empty endpoint")
	}
}

func TestSidecar_NotConfigured(t *testing.T) {
	c := NewSidecar("")
	input := &Input{OperationType: "query", Depth: 3, FieldCount: 10}
	result, err := c.Evaluate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed when OPA not configured, got blocked: %s", result.Reason)
	}
}

func TestSidecar_AllowsQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result": {"allowed": true}}`))
	}))
	defer srv.Close()

	client := NewSidecar(srv.URL)
	input := &Input{OperationType: "query", Depth: 3, FieldCount: 10}
	result, err := client.Evaluate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed, got blocked: %s", result.Reason)
	}
}

func TestSidecar_BlocksQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result": {"allowed": false, "reason": "query depth exceeded"}}`))
	}))
	defer srv.Close()

	client := NewSidecar(srv.URL)
	input := &Input{OperationType: "query", Depth: 100}
	result, err := client.Evaluate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Fatal("expected blocked, got allowed")
	}
	if result.Reason != "query depth exceeded" {
		t.Errorf("expected reason 'query depth exceeded', got %q", result.Reason)
	}
}

func TestSidecar_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewSidecar(srv.URL)
	input := &Input{OperationType: "query"}
	_, err := client.Evaluate(input)
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}

func TestSidecar_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {}
	}))
	defer srv.Close()

	client := NewSidecar(srv.URL)
	client.httpClient.Timeout = 1 // 1ms timeout
	input := &Input{OperationType: "query"}
	_, err := client.Evaluate(input)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestSidecar_SendsInput(t *testing.T) {
	var receivedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		receivedBody = string(buf)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result": {"allowed": true}}`))
	}))
	defer srv.Close()

	client := NewSidecar(srv.URL)
	input := &Input{
		OperationType: "mutation",
		Depth:         5,
		FieldCount:    20,
		OperationName: "CreateUser",
		FieldPaths:    []string{"user", "user.name", "user.email"},
		TenantID:      "acme",
	}
	_, err := client.Evaluate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedBody == "" {
		t.Fatal("expected request body to be sent")
	}
	if !strings.Contains(receivedBody, "mutation") || !strings.Contains(receivedBody, "CreateUser") || !strings.Contains(receivedBody, "tenant_id") {
		t.Errorf("request body missing query info fields: %s", receivedBody)
	}
}
