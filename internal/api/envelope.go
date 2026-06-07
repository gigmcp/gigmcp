package api

import (
	"bytes"
	"fmt"
	"net/http"
)

// envelopeWriter intercepts responses from the inner mux and rewrites bare
// 404/405 text/plain replies (emitted by Go's ServeMux) as JSON envelopes so
// all /api/* error responses share the same shape (spec §5).
type envelopeWriter struct {
	http.ResponseWriter
	buf    bytes.Buffer
	status int
}

func (ew *envelopeWriter) WriteHeader(code int) {
	ew.status = code
}

func (ew *envelopeWriter) Write(b []byte) (int, error) {
	return ew.buf.Write(b)
}

// flush writes the (possibly rewritten) response to the real ResponseWriter.
func (ew *envelopeWriter) flush() {
	if ew.status == http.StatusNotFound || ew.status == http.StatusMethodNotAllowed {
		code := codeNotFound
		msg := "not found"
		if ew.status == http.StatusMethodNotAllowed {
			code = codeMethodNotAllowed
			msg = fmt.Sprintf("method not allowed; allowed: %s", ew.Header().Get("Allow"))
			// Preserve the Allow header on the real response.
			ew.ResponseWriter.Header().Set("Allow", ew.Header().Get("Allow"))
		}
		writeErr(ew.ResponseWriter, ew.status, code, msg)
		return
	}
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
