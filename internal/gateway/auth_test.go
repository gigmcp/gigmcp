package gateway_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gigmcp/gigmcp/internal/gateway"
)

func TestRequireBearer(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := gateway.RequireBearer("sekrit", next)

	cases := []struct {
		name     string
		header   string
		want     int
		wantAuth bool
	}{
		{"no header", "", http.StatusUnauthorized, true},
		{"wrong scheme", "Basic sekrit", http.StatusUnauthorized, true},
		{"wrong token", "Bearer nope", http.StatusUnauthorized, true},
		{"token as prefix", "Bearer sekrit2", http.StatusUnauthorized, true},
		{"correct", "Bearer sekrit", http.StatusOK, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("got %d, want %d", rec.Code, tc.want)
			}
			if gotAuth := rec.Header().Get("WWW-Authenticate"); tc.wantAuth && gotAuth != "Bearer" {
				t.Errorf("WWW-Authenticate: got %q, want %q", gotAuth, "Bearer")
			}
		})
	}
}
