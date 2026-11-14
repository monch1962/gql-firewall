package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── R99: lexer-desync nesting bombs must be stopped at the handler ──────────
// R98 bounded query nesting with a pre-parse scan, but the scan ended two
// literals in the wrong place: a `#` comment was scanned to '\n' only (the
// lexer ends it at any control byte, e.g. a lone '\r') and a block string was
// scanned to the first `"""` of a closing quote run (the lexer consumes the
// whole run). Either desync makes the scanner swallow the rest of the document
// while gqlparser keeps lexing it, so a nesting bomb behind a CR-terminated
// comment or after a four-quote block string reached the recursive descent —
// the CAPEC-130 amplifier R98 was meant to cut off.
//
// CAPEC-130: Excessive Allocation.
func TestAttack_LexerDesyncNestingBombRejected(t *testing.T) {
	const depth = 1500

	cases := []struct {
		name  string
		query string
	}{
		{
			// A lone CR ends the comment for gqlparser, so everything after it
			// is parsed as a selection set.
			name:  "carriage-return comment terminator",
			query: "# comment\r" + strings.Repeat("{a", depth) + strings.Repeat("}", depth),
		},
		{
			// The four-quote closing run is consumed whole by the lexer; a
			// scanner that stops after three leaves a quote that swallows the
			// bracket bomb as if it were string content.
			name:  "four-quote block string run",
			query: `{ f(a: ["""x""""` + strings.Repeat("[", depth) + strings.Repeat("]", depth) + "]) }",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstreamCalls := 0
			up := testUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls++
				w.WriteHeader(http.StatusOK)
			})
			defer up.Close()

			evalCalls := 0
			h := MustNew(up.URL, &countingEvaluator{calls: &evalCalls})
			h.ParseTimeout = 5 * time.Second

			body, err := json.Marshal(map[string]string{"query": tc.query})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			start := time.Now()
			h.ServeHTTP(w, req)
			elapsed := time.Since(start)

			if w.Code != http.StatusBadRequest && w.Code != http.StatusForbidden {
				t.Errorf("expected 400/403 for desynced nesting bomb, got %d (body=%s)", w.Code, w.Body.String())
			}
			if upstreamCalls != 0 {
				t.Errorf("upstream called %d times for a rejected bomb", upstreamCalls)
			}
			if evalCalls != 0 {
				t.Errorf("policy evaluated %d times for a rejected bomb (parse-time bound must run first)", evalCalls)
			}
			if elapsed > 2*time.Second {
				t.Errorf("rejection took %s, want < 2s", elapsed)
			}

			var payload map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
				t.Errorf("response is not valid JSON: %v (%q)", err, w.Body.String())
			}
		})
	}
}
