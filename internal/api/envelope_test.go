package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestEnvelopePassthroughHandlerJSON verifies that a handler inside envelopeMux
// that calls writeErr (Content-Type: application/json) has its response passed
// through byte-for-byte — the envelope interceptor must NOT clobber it with a
// generic message (regression for the status-only rewrite bug).
func TestEnvelopePassthroughHandlerJSON(t *testing.T) {
	const wantMsg = "profile 42 not found"

	inner := http.NewServeMux()
	inner.HandleFunc("GET /api/probe", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, codeNotFound, wantMsg)
	})

	ts := httptest.NewServer(envelopeMux(inner))
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/api/probe")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", resp.StatusCode, b)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type: want application/json, got %q", ct)
	}
	if !strings.Contains(string(b), wantMsg) {
		t.Fatalf("handler message %q was clobbered; body: %s", wantMsg, b)
	}
}

// TestEnvelopeWriteHeaderOnce verifies that calling WriteHeader twice on an
// envelopeWriter only records the first status (net/http semantics).
func TestEnvelopeWriteHeaderOnce(t *testing.T) {
	rec := httptest.NewRecorder()
	ew := &envelopeWriter{ResponseWriter: rec, status: http.StatusOK}
	ew.WriteHeader(http.StatusTeapot)
	ew.WriteHeader(http.StatusInternalServerError) // must be ignored
	if ew.status != http.StatusTeapot {
		t.Fatalf("WriteHeader: second call must not overwrite first; got %d", ew.status)
	}
}
