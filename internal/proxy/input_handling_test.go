package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/monch1962/gql-firewall/internal/opa"
	"github.com/monch1962/gql-firewall/internal/parser"
)

// ── Batch Request Tests ───────────────────────────────────────────

func TestBatch_ValidBatchForwards(t *testing.T) {
	callCount := 0
	var capturedBody []byte
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"data": {"hello": "world"}}, {"data": {"goodbye": "world"}}]`))
	})
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})

	batch := batchGraphQLBody{
		{Query: "{ hello }"},
		{Query: "{ goodbye }"},
	}
	body, _ := json.Marshal(batch)

	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for valid batch, got %d", resp.StatusCode)
	}
	if callCount != 1 {
		t.Errorf("expected upstream called once, got %d calls", callCount)
	}
	// Verify the original batch body was forwarded
	if !bytes.Contains(capturedBody, []byte("hello")) || !bytes.Contains(capturedBody, []byte("goodbye")) {
		t.Errorf("expected both queries in forwarded body, got: %s", string(capturedBody))
	}
}

func TestBatch_AnyBlockedRejectsAll(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		t.Error("should not reach upstream when batch item is blocked")
	})
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: false, Reason: "depth exceeded"}})

	batch := batchGraphQLBody{
		{Query: "{ allowed }"},
		{Query: "{ blocked }"},
	}
	body, _ := json.Marshal(batch)

	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 when batch item blocked, got %d", resp.StatusCode)
	}
	if callCount != 0 {
		t.Errorf("expected upstream not called, got %d calls", callCount)
	}
	respBody, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(respBody, []byte("blocked")) {
		t.Errorf("expected block reason in response, got: %s", string(respBody))
	}
}

func TestBatch_EmptyBatch(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not reach upstream") })
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})

	body := []byte(`[]`)

	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for empty batch, got %d", resp.StatusCode)
	}
}

func TestBatch_ItemWithEmptyQuery(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not reach upstream") })
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})

	body := []byte(`[{"query": ""}]`)

	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for batch item with empty query, got %d", resp.StatusCode)
	}
}

func TestBatch_InvalidJSON(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not reach upstream") })
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})

	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(`[not-json`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid batch JSON, got %d", resp.StatusCode)
	}
}

// ── GET Request Tests ─────────────────────────────────────────────

func TestGET_WithVariables(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Verify the forwarded body includes the variables
		body, _ := io.ReadAll(r.Body)
		if !bytes.Contains(body, []byte("42")) {
			t.Errorf("expected variables in forwarded body, got: %s", string(body))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": {"user": {"name": "Alice"}}}`))
	})
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})
	req := httptest.NewRequest("GET", "/graphql?query={user(id:42){name}}&variables={\"id\":42}", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount != 1 {
		t.Errorf("expected upstream called once, got %d calls", callCount)
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGET_BlockedByOPA(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { callCount++ })
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: false, Reason: "introspection blocked"}})
	req := httptest.NewRequest("GET", "/graphql?query={__schema{types{name}}}", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount != 0 {
		t.Errorf("expected upstream not called for blocked GET, got %d calls", callCount)
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestGET_WithoutQueryReturns400(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { callCount++ })
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})
	req := httptest.NewRequest("GET", "/graphql", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount != 0 {
		t.Errorf("expected upstream not called, got %d calls", callCount)
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for GET without query, got %d", w.Code)
	}
}

func TestGET_WithOperationName(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		body, _ := io.ReadAll(r.Body)
		if !bytes.Contains(body, []byte("GetUser")) {
			t.Errorf("expected operationName in forwarded GET body, got: %s", string(body))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": {"user": {"name": "Bob"}}}`))
	})
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: true}})
	req := httptest.NewRequest("GET", "/graphql?query=query+GetUser{user{name}}&operationName=GetUser", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount != 1 {
		t.Errorf("expected upstream called once, got %d calls", callCount)
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ── Variables in OPA Input Tests ──────────────────────────────────

// evalSpy captures the QueryInfo passed to Evaluate for inspection.
type evalSpy struct {
	lastInfo *parser.QueryInfo
	result   *opa.Result
}

func (s *evalSpy) Evaluate(info *parser.QueryInfo) (*opa.Result, error) {
	s.lastInfo = info
	return s.result, nil
}

func TestVariables_RequestBodyPassedToOPA(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": {"ok": true}}`))
	})
	defer up.Close()

	spy := &evalSpy{result: &opa.Result{Allowed: true}}
	h := MustNew(up.URL, spy)

	body := `{"query": "query($id: ID!) { user(id: $id) { name } }", "variables": {"id": 42}}`
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if spy.lastInfo == nil {
		t.Fatal("expected QueryInfo to be passed to evaluator")
	}
	if len(spy.lastInfo.RequestVariables) == 0 {
		t.Error("expected RequestVariables to be populated from request body")
	}
	if !bytes.Contains(spy.lastInfo.RequestVariables, []byte("42")) {
		t.Errorf("expected variables to contain 42, got: %s", string(spy.lastInfo.RequestVariables))
	}
}

func TestVariables_GETQueryPassedToOPA(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": {"ok": true}}`))
	})
	defer up.Close()

	spy := &evalSpy{result: &opa.Result{Allowed: true}}
	h := MustNew(up.URL, spy)

	req := httptest.NewRequest("GET", "/graphql?query={hello}&variables={\"x\":1}", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if spy.lastInfo == nil {
		t.Fatal("expected QueryInfo to be passed to evaluator")
	}
	if len(spy.lastInfo.RequestVariables) == 0 {
		t.Error("expected RequestVariables from GET query param")
	}
}

func TestVariables_NoVariablesInBody(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": {"ok": true}}`))
	})
	defer up.Close()

	spy := &evalSpy{result: &opa.Result{Allowed: true}}
	h := MustNew(up.URL, spy)

	body := `{"query": "{ hello }"}`
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if spy.lastInfo != nil && len(spy.lastInfo.RequestVariables) > 0 {
		t.Error("expected RequestVariables to be empty")
	}
}
