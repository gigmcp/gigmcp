package api

import (
	"encoding/json"
	"log"
	"net/http"
)

// Error-code constants (spec §5).
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

// writeErr emits the uniform {"error":{"code","message"}} envelope (spec §5).
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
		// http.MaxBytesReader sets a sentinel error whose message contains
		// "http: request body too large".
		if err.Error() == "http: request body too large" {
			writeErr(w, http.StatusRequestEntityTooLarge, codeInvalid, "request body too large")
			return false
		}
		writeErr(w, http.StatusBadRequest, codeInvalid, "invalid JSON body")
		return false
	}
	return true
}
