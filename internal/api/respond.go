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
