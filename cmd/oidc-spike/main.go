// Command oidc-spike is a THROWAWAY proof of the full OIDC code+PKCE flow
// against the dev Zitadel: NewProvider → AuthCodeURL(state, nonce, PKCE) →
// browser login → callback → Exchange → Verify → claims (incl. the Zitadel
// roles claim). Delete this file before committing Task 1.
//
// Run:  SPIKE_CLIENT_ID=<client-id> go run ./cmd/oidc-spike
// then open http://localhost:8080/ and log in as the Zitadel admin.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func main() {
	issuer := os.Getenv("SPIKE_ISSUER")
	if issuer == "" {
		issuer = "http://localhost:8082"
	}
	clientID := os.Getenv("SPIKE_CLIENT_ID")
	if clientID == "" {
		log.Fatal("set SPIKE_CLIENT_ID to the Zitadel app's client id")
	}
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatalf("discovery: %v", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	conf := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: os.Getenv("SPIKE_CLIENT_SECRET"), // empty for the PKCE public client
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://localhost:8080/api/auth/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	const state, nonce = "spike-state", "spike-nonce"
	pkce := oauth2.GenerateVerifier()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r,
			conf.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(pkce)),
			http.StatusFound)
	})
	http.HandleFunc("/api/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		tok, err := conf.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(pkce))
		if err != nil {
			http.Error(w, "exchange: "+err.Error(), http.StatusBadGateway)
			return
		}
		rawID, ok := tok.Extra("id_token").(string)
		if !ok {
			http.Error(w, "no id_token in response", http.StatusBadGateway)
			return
		}
		idt, err := verifier.Verify(r.Context(), rawID)
		if err != nil {
			http.Error(w, "verify: "+err.Error(), http.StatusUnauthorized)
			return
		}
		if idt.Nonce != nonce {
			http.Error(w, "nonce mismatch", http.StatusUnauthorized)
			return
		}
		var claims map[string]any
		if err := idt.Claims(&claims); err != nil {
			http.Error(w, "claims: "+err.Error(), http.StatusBadGateway)
			return
		}
		log.Printf("SPIKE OK issuer=%s sub=%s", idt.Issuer, idt.Subject)
		log.Printf("SPIKE roles claim: %#v", claims["urn:zitadel:iam:org:project:roles"])
		fmt.Fprintf(w, "SPIKE OK\nissuer=%s\nsub=%s\nclaims=%v\n", idt.Issuer, idt.Subject, claims)
	})
	log.Println("spike on http://localhost:8080/ — open it in a browser")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
