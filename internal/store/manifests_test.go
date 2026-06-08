package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func openTestStore(t *testing.T) Store {
	t.Helper()
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func sampleRecord() ManifestRecord {
	return ManifestRecord{
		Server:       "slack-mcp",
		Version:      "1.4.2",
		Digest:       "sha256:abc",
		Tier:         "sealed",
		Entrypoint:   "/server",
		AllowedHosts: []string{"slack.com", "*.slack.com"},
		Injections: []Injection{{
			ID: "slack_bot_token", Header: "Authorization",
			Format: "Bearer {token}", Placeholder: "gigph-aabbcc",
		}},
		Tools:        []ToolEntry{{Name: "send_message", Default: true}, {Name: "admin", Default: false}},
		ManifestHash: "hash-v1",
	}
}

func TestManifestRoundTrip(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	if err := st.PutManifest(ctx, sampleRecord()); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetManifest(ctx, "slack-mcp")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "1.4.2" || got.Tier != "sealed" || got.Entrypoint != "/server" {
		t.Fatalf("bad scalar fields: %+v", got)
	}
	if len(got.AllowedHosts) != 2 || got.AllowedHosts[1] != "*.slack.com" {
		t.Fatalf("bad hosts: %v", got.AllowedHosts)
	}
	if len(got.Injections) != 1 || got.Injections[0].Placeholder != "gigph-aabbcc" {
		t.Fatalf("bad injections: %+v", got.Injections)
	}
	if len(got.Tools) != 2 || !got.Tools[0].Default || got.Tools[1].Default {
		t.Fatalf("bad tools: %+v", got.Tools)
	}
	if !got.NeedsReconsent() {
		t.Fatal("fresh install (consented_hash empty) must need consent")
	}
}

func TestConsentLifecycle(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	rec := sampleRecord()
	if err := st.PutManifest(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordConsent(ctx, "slack-mcp", "hash-v1"); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetManifest(ctx, "slack-mcp")
	if got.NeedsReconsent() {
		t.Fatal("consented manifest must not need re-consent")
	}
	// Version bump with new hash: consent must be PRESERVED (and now stale).
	rec.Version = "1.5.0"
	rec.ManifestHash = "hash-v2"
	if err := st.PutManifest(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetManifest(ctx, "slack-mcp")
	if got.ConsentedHash != "hash-v1" || !got.NeedsReconsent() {
		t.Fatalf("upgrade must preserve consented hash and flip NeedsReconsent: %+v", got)
	}
	if err := st.RecordConsent(ctx, "missing", "x"); !errors.Is(err, ErrManifestNotFound) {
		t.Fatalf("consent on missing server: %v, want ErrManifestNotFound", err)
	}
}

func TestPutGetManifestPersistsCredentialMeta(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	rec := ManifestRecord{
		Server: "gmail", Version: "1.0.0", Digest: "sha256:x", Tier: "sealed",
		Entrypoint: "/app/server", AllowedHosts: []string{"gmail.googleapis.com"},
		Injections: []Injection{{
			ID: "api", Type: "oauth2", Provider: "gmail", Vendor: "google",
			Scopes: []string{"read", "send"},
			Header: "Authorization", Format: "Bearer {token}", Placeholder: "gigph-abc",
		}},
		Tools:        []ToolEntry{{Name: "send", Default: true}},
		ManifestHash: "h1",
	}
	if err := st.PutManifest(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetManifest(ctx, "gmail")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Injections) != 1 {
		t.Fatalf("want 1 injection, got %d", len(got.Injections))
	}
	inj := got.Injections[0]
	if inj.Type != "oauth2" || inj.Provider != "gmail" {
		t.Fatalf("type/provider not persisted: %+v", inj)
	}
	if inj.Vendor != "google" {
		t.Fatalf("vendor not persisted: %+v", inj)
	}
	if len(inj.Scopes) != 2 || inj.Scopes[0] != "read" || inj.Scopes[1] != "send" {
		t.Fatalf("scopes not persisted: %+v", inj.Scopes)
	}
}

func TestGetManifestNotFoundAndDelete(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	if _, err := st.GetManifest(ctx, "nope"); !errors.Is(err, ErrManifestNotFound) {
		t.Fatalf("want ErrManifestNotFound, got %v", err)
	}
	if err := st.PutManifest(ctx, sampleRecord()); err != nil {
		t.Fatal(err)
	}
	if list, err := st.ListManifests(ctx); err != nil || len(list) != 1 {
		t.Fatalf("ListManifests: %v %v", list, err)
	}
	if err := st.DeleteManifest(ctx, "slack-mcp"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetManifest(ctx, "slack-mcp"); !errors.Is(err, ErrManifestNotFound) {
		t.Fatal("manifest should be gone")
	}
	// DeleteServer removes the servers row.
	if _, err := st.EnsureServer(ctx, "slack-mcp", "/tmp/x"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteServer(ctx, "slack-mcp"); err != nil {
		t.Fatal(err)
	}
	servers, _ := st.ListServers(ctx)
	if len(servers) != 0 {
		t.Fatalf("server should be gone: %v", servers)
	}
}
