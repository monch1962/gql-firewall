package opa

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/monch1962/gql-firewall/internal/parser"
)

func TestConfigured(t *testing.T) {
	c := New("")
	if c.Configured() {
		t.Error("expected Configured()=false for empty endpoint")
	}
	c2 := New("http://localhost:8181")
	if !c2.Configured() {
		t.Error("expected Configured()=true for non-empty endpoint")
	}
}

func TestEvaluate_AllowsByDefaultWhenNotConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result": {"allowed": true}}`))
	}))
	defer srv.Close()

	client := New(srv.URL)
	info := &parser.QueryInfo{
		OperationType: "query",
		Depth:         3,
		FieldCount:    10,
	}
	result, err := client.Evaluate(info)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed, got blocked: %s", result.Reason)
	}
}

func TestEvaluate_BlocksQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result": {"allowed": false, "reason": "query depth exceeded"}}`))
	}))
	defer srv.Close()

	client := New(srv.URL)
	info := &parser.QueryInfo{
		OperationType: "query",
		Depth:         100,
	}
	result, err := client.Evaluate(info)
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

func TestEvaluate_OPAError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := New(srv.URL)
	info := &parser.QueryInfo{OperationType: "query"}
	_, err := client.Evaluate(info)
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}

func TestEvaluate_OPATimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// OPA timeout — never responds
		select {}
	}))
	defer srv.Close()

	client := New(srv.URL)
	client.httpClient.Timeout = 1 // 1ms timeout to ensure fast test
	info := &parser.QueryInfo{OperationType: "query"}
	_, err := client.Evaluate(info)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestNew_EmptyURL(t *testing.T) {
	client := New("")
	if client == nil {
		t.Fatal("expected non-nil client for empty URL")
	}
	// Should return allow-by-default when OPA is not configured
	info := &parser.QueryInfo{OperationType: "query"}
	result, err := client.Evaluate(info)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed (OPA disabled), got blocked: %s", result.Reason)
	}
}

func TestEvaluate_SendsQueryInfo(t *testing.T) {
	var receivedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		receivedBody = string(buf)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result": {"allowed": true}}`))
	}))
	defer srv.Close()

	client := New(srv.URL)
	info := &parser.QueryInfo{
		OperationType: "mutation",
		Depth:         5,
		FieldCount:    20,
		OperationName: "CreateUser",
		FieldPaths:    []string{"user", "user.name", "user.email"},
	}
	_, err := client.Evaluate(info)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedBody == "" {
		t.Fatal("expected request body to be sent")
	}
	// Should contain query info fields
	if !strings.Contains(receivedBody, "mutation") || !strings.Contains(receivedBody, "CreateUser") {
		t.Errorf("request body missing query info fields: %s", receivedBody)
	}
}

