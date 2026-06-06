package gateway

import (
	"crypto/subtle"
	"net/http"
)

// RequireBearer rejects requests whose Authorization header is not exactly
// "Bearer <token>", using a constant-time comparison.
func RequireBearer(token string, next http.Handler) http.Handler {
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		// NOTE: ConstantTimeCompare returns 0 immediately on length mismatch
		// (the length check itself is not constant-time), but the expected
		// length is fixed at startup and not secret, so leaking it is fine.
		if subtle.ConstantTimeCompare(got, want) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
