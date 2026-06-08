package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

// Error-code constants used in the uniform error envelope.
const (
	codeUnauthenticated  = "unauthenticated"
	codeForbidden        = "forbidden"
	codeNotFound         = "not_found"
	codeMethodNotAllowed = "method_not_allowed"
	codeInvalid          = "invalid"
	codeConflict         = "conflict"
	codeInternal         = "internal"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("WARN: write JSON response: %v", err)
	}
}

// writeErr emits the uniform {"error":{"code","message"}} envelope.
func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

// decodeJSON reads up to maxBytes from r.Body, decodes it into dst, and
// returns true on success. On failure it writes the appropriate 400/413
// envelope itself and returns false. Pass 64<<10 (64 KiB) for typical
// handler bodies.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, codeInvalid, "request body too large")
			return false
		}
		// Pass the decoder error through so callers can diagnose strict-mode
		// rejections (e.g. `json: unknown field "slugg"`). Decode errors
		// describe only the client's own bytes; nothing internal leaks.
		writeErr(w, http.StatusBadRequest, codeInvalid, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}
