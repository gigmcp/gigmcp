package registry

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/oci"
	"github.com/gigmcp/gigmcp/internal/oci/ocitest"
	"github.com/gigmcp/gigmcp/internal/store"
)

func newTestInstaller(t *testing.T, autoConsent bool) (*IndexInstaller, store.Store) {
	t.Helper()
	layoutDir := t.TempDir()
	digest, err := ocitest.WriteLayoutImage(layoutDir, map[string][]byte{
		"app/server": []byte("fake-echo-binary"),
	})
	if err != nil {
		t.Fatal(err)
	}
	url, pub := writeSignedIndex(t,
		fixtureManifest("echo", "0.1.0", digest),
		fixtureManifest("echo", "0.2.0", digest),
	)
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &IndexInstaller{
		Store:       st,
		Client:      &Client{IndexURL: url, PublicKeyHex: pub},
		Puller:      &oci.Puller{LayoutDir: layoutDir},
		DataDir:     t.TempDir(),
		AutoConsent: autoConsent,
	}, st
}

func TestInstallRecordsServerAndManifest(t *testing.T) {
	inst, st := newTestInstaller(t, true)
	ctx := context.Background()
	srv, err := inst.Install(ctx, "echo@0.1.0")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if srv.Name != "echo" || !strings.Contains(srv.Binary, "echo@0.1.0") {
		t.Fatalf("bad server: %+v", srv)
	}
	if data, err := os.ReadFile(srv.Binary); err != nil || string(data) != "fake-echo-binary" {
		t.Fatalf("extracted binary: %q %v", data, err)
	}
	rec, err := st.GetManifest(ctx, "echo")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Version != "0.1.0" || rec.AllowedHosts[0] != "api.example.com" {
		t.Fatalf("bad record: %+v", rec)
	}
	if len(rec.Injections) != 1 || !strings.HasPrefix(rec.Injections[0].Placeholder, "gigph-") ||
		len(rec.Injections[0].Placeholder) < 20 {
		t.Fatalf("placeholder must be generated high-entropy: %+v", rec.Injections)
	}
	if rec.NeedsReconsent() {
		t.Fatal("AutoConsent install must be consented")
	}
	if len(rec.Tools) != 2 || !rec.Tools[0].Default || rec.Tools[1].Default {
		t.Fatalf("tools must round-trip: %+v", rec.Tools)
	}
}

func TestInstallIdempotentAndUpgradeFlipsConsent(t *testing.T) {
	inst, st := newTestInstaller(t, true)
	ctx := context.Background()
	if _, err := inst.Install(ctx, "echo@0.1.0"); err != nil {
		t.Fatal(err)
	}
	rec1, _ := st.GetManifest(ctx, "echo")
	if _, err := inst.Install(ctx, "echo@0.1.0"); err != nil { // re-install: no-op
		t.Fatal(err)
	}
	rec2, _ := st.GetManifest(ctx, "echo")
	if rec2.Injections[0].Placeholder != rec1.Injections[0].Placeholder {
		t.Fatal("idempotent re-install must not regenerate placeholders")
	}

	// Upgrade WITHOUT AutoConsent: consent goes stale.
	inst.AutoConsent = false
	if _, err := inst.Install(ctx, "echo"); err != nil { // latest = 0.2.0
		t.Fatal(err)
	}
	rec3, _ := st.GetManifest(ctx, "echo")
	if rec3.Version != "0.2.0" || !rec3.NeedsReconsent() {
		t.Fatalf("upgrade must record 0.2.0 and need re-consent: %+v", rec3)
	}
}

func TestInstallByDigestRef(t *testing.T) {
	inst, _ := newTestInstaller(t, true)
	ix, err := inst.Client.FetchIndex(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m, _ := ix.Resolve("echo@0.1.0")
	if _, err := inst.Install(context.Background(), m.Image.Digest); err != nil {
		t.Fatalf("install by sha256 ref: %v", err)
	}
}

func TestUninstallRemovesEverything(t *testing.T) {
	inst, st := newTestInstaller(t, true)
	ctx := context.Background()
	srv, err := inst.Install(ctx, "echo@0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Uninstall(ctx, "echo"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetManifest(ctx, "echo"); err == nil {
		t.Fatal("manifest must be deleted")
	}
	if servers, _ := st.ListServers(ctx); len(servers) != 0 {
		t.Fatal("server row must be deleted")
	}
	if _, err := os.Stat(srv.Binary); !os.IsNotExist(err) {
		t.Fatal("extracted files must be removed")
	}
}

func TestInstallUnknownRefFails(t *testing.T) {
	inst, _ := newTestInstaller(t, true)
	if _, err := inst.Install(context.Background(), "nope@1.0.0"); err == nil {
		t.Fatal("unknown ref must fail")
	}
}
