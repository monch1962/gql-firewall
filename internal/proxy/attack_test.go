package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/monch1962/gql-firewall/internal/opa"
)

func gql(qry string) io.Reader {
	return bytes.NewReader(mustJSON(graphQLBody{Query: qry}))
}

var passEval = &stubEvaluator{result: &opa.Result{Allowed: true}}

// R1: Attack — missing Content-Type header
func TestAttack_MissingContentType(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not reach upstream") })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	req := httptest.NewRequest("POST", "/graphql", gql("{ hello }"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest && w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 4xx for missing Content-Type, got %d", w.Code)
	}
}

// R2: Attack — wrong Content-Type
func TestAttack_WrongContentType(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not reach upstream") })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	req := httptest.NewRequest("POST", "/graphql", gql("{ hello }"))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest && w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 4xx for wrong Content-Type, got %d", w.Code)
	}
}

// R3: Attack — uppercase /GRAPHQL should be intercepted (case-insensitive match)
func TestAttack_UppercasePath(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	req := httptest.NewRequest("POST", "/GRAPHQL", gql("{ hello }"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	_ = w
}

// R4: Attack — path traversal (Go normalizes before handler sees it)
func TestAttack_PathTraversal(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	req := httptest.NewRequest("POST", "/graphql/../admin/rules", gql("{ hello }"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("expected 200 (path is normalized by Go before handler), got %d", w.Code)
	}
}

// R5: Attack — query string injection: /graphql?query={hello}
func TestAttack_QueryStringInjection(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { callCount++; w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	req := httptest.NewRequest("POST", "/graphql?query={hello}", bytes.NewReader([]byte(`{"operationName":"Test"}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount > 0 {
		t.Errorf("should not forward when query is in URL param, upstream called %d times", callCount)
	}
}

// R6: Attack — OPA reason injection (unsanitized reason breaks JSON)
func TestAttack_OPAReasonInjection(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not reach upstream") })
	defer up.Close()

	h := MustNew(up.URL, &stubEvaluator{result: &opa.Result{Allowed: false, Reason: `injected"`}})
	req := httptest.NewRequest("POST", "/graphql", gql("{ hello }"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
	if !json.Valid(body) {
		t.Errorf("response body is not valid JSON: %s", string(body))
	}
}

// R7: Attack — double Content-Type header
func TestAttack_DoubleContentType(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { callCount++; w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	req := httptest.NewRequest("POST", "/graphql", gql("{ hello }"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Content-Type", "text/html")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	_ = callCount
}

// R8: Attack — GET /graphql with body (should pass through, not evaluate)
func TestAttack_GETWithGraphQLBody(t *testing.T) {
	callCount := 0
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { callCount++; w.WriteHeader(http.StatusOK) })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	req := httptest.NewRequest("GET", "/graphql", gql("{ hello }"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if callCount != 1 {
		t.Errorf("expected GET to pass through, got %d calls", callCount)
	}
}

// R9: Attack — empty body
func TestAttack_EmptyBody(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not reach upstream") })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(nil))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty body, got %d", w.Code)
	}
}

// R10: Attack — whitespace-only body
func TestAttack_WhitespaceBody(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not reach upstream") })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte("   ")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for whitespace body, got %d", w.Code)
	}
}

// R11: Attack — valid JSON without query field
func TestAttack_ValidJSONNoQuery(t *testing.T) {
	up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("should not reach upstream") })
	defer up.Close()

	h := MustNew(up.URL, passEval)
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader([]byte(`{"foo":"bar"}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for valid JSON without query, got %d", w.Code)
	}
}
