package api

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
)

// envelopeWriter intercepts responses from the inner mux and rewrites bare
// 404/405 text/plain replies (emitted by Go's ServeMux) as JSON envelopes so
// all /api/* error responses share the same shape.
//
// NOTE: this wrapper buffers the full response body until the handler returns
// and does NOT implement http.Flusher. Streaming handlers (SSE, chunked) must
// not be mounted inside envelopeMux.
type envelopeWriter struct {
	http.ResponseWriter
	buf         bytes.Buffer
	status      int
	wroteHeader bool
}

func (ew *envelopeWriter) WriteHeader(code int) {
	// First call wins — matches net/http semantics.
	if ew.wroteHeader {
		return
	}
	ew.wroteHeader = true
	ew.status = code
}

func (ew *envelopeWriter) Write(b []byte) (int, error) {
	if !ew.wroteHeader {
		ew.WriteHeader(http.StatusOK)
	}
	return ew.buf.Write(b)
}

// flush writes the (possibly rewritten) response to the real ResponseWriter.
// Only bare text/plain 404/405 responses (the ServeMux/http.Error signature)
// are rewritten as JSON envelopes. If the handler already wrote
// application/json (e.g. via writeErr), the bytes are passed through
// untouched so handler-authored messages are preserved.
func (ew *envelopeWriter) flush() {
	if ew.status == http.StatusNotFound || ew.status == http.StatusMethodNotAllowed {
		ct := ew.Header().Get("Content-Type")
		if !strings.HasPrefix(ct, "application/json") {
			// Bare text/plain from ServeMux — rewrite as JSON envelope.
			code := codeNotFound
			msg := "not found"
			if ew.status == http.StatusMethodNotAllowed {
				code = codeMethodNotAllowed
				msg = fmt.Sprintf("method not allowed; allowed: %s", ew.Header().Get("Allow"))
				// The Allow header survives because ew.Header() and
				// ew.ResponseWriter.Header() are the same underlying map (the
				// envelopeWriter embeds the ResponseWriter without buffering
				// headers). A future refactor that buffers headers must
				// explicitly copy Allow to the real writer here.
			}
			writeErr(ew.ResponseWriter, ew.status, code, msg)
			return
		}
	}
	// Handler already produced a well-formed response — pass through as-is.
	ew.ResponseWriter.WriteHeader(ew.status)
	_, _ = ew.ResponseWriter.Write(ew.buf.Bytes())
}

// envelopeMux wraps h so that bare 404/405 responses are converted to JSON.
func envelopeMux(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ew := &envelopeWriter{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(ew, r)
		ew.flush()
	})
}
