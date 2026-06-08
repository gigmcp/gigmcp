package gateway

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/store"
)

// fakeEnsurer stands in for the broker's EnsureFreshToken in resolver tests.
type fakeEnsurer struct {
	token     string
	calls     int
	gotVendor string // the vendor key the resolver keyed the token off
}

func (f *fakeEnsurer) EnsureFreshToken(_ context.Context, _ int64, vendor string) (string, error) {
	f.calls++
	f.gotVendor = vendor
	return f.token, nil
}

func TestResolveOAuthBranchInjectsBearer(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	// Install a manifest whose first credential is oauth2: connector provider
	// "gmail" but canonical vendor "google" — the broker must key off vendor.
	if err := st.PutManifest(ctx, store.ManifestRecord{
		Server: "gmail", Version: "1.0.0", Digest: "sha256:x", Tier: "sealed",
		Entrypoint: "/app/server", AllowedHosts: []string{"gmail.googleapis.com"},
		Injections: []store.Injection{{
			ID: "oauth", Type: "oauth2", Provider: "gmail", Vendor: "google",
			Scopes: []string{"email"}, Header: "Authorization",
			Format: "Bearer {token}", Placeholder: "PH_HIGH_ENTROPY_SENTINEL",
		}},
		ManifestHash: "h1",
	}); err != nil {
		t.Fatal(err)
	}

	ens := &fakeEnsurer{token: "live-access-token"}
	r := &CredResolver{Store: st, Broker: ens}

	// Tenant is the user id as a decimal string (UserTenant). No profile join needed.
	cred, err := r.Resolve(proxy.Identity{Server: "gmail", Tenant: store.UserTenant(42)}, "gmail.googleapis.com")
	if err != nil {
		t.Fatal(err)
	}
	if cred.RealSecret != "live-access-token" {
		t.Fatalf("bearer not the fresh access token: %q", cred.RealSecret)
	}
	if cred.InjectHeader != "Authorization" || cred.InjectFormat != "Bearer {token}" {
		t.Fatalf("injection schema wrong: %+v", cred)
	}
	if cred.Placeholder != "PH_HIGH_ENTROPY_SENTINEL" {
		t.Fatalf("placeholder must come from the manifest injection: %q", cred.Placeholder)
	}
	if len(cred.AllowedHosts) != 1 || cred.AllowedHosts[0] != "gmail.googleapis.com" {
		t.Fatalf("allowed hosts must come from manifest entitlements: %v", cred.AllowedHosts)
	}
	if ens.calls != 1 {
		t.Fatalf("EnsureFreshToken must be called exactly once, got %d", ens.calls)
	}
	if ens.gotVendor != "google" {
		t.Fatalf("token must be keyed off the canonical vendor, got %q", ens.gotVendor)
	}
}

// TestResolveOAuthFallsBackToProvider proves the resolver keys the token off the
// per-connector Provider slug when the manifest has no backfilled Vendor (so an
// un-backfilled manifest still resolves instead of crashing).
func TestResolveOAuthFallsBackToProvider(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	if err := st.PutManifest(ctx, store.ManifestRecord{
		Server: "gmail", Version: "1.0.0", Digest: "sha256:x", Tier: "sealed",
		Entrypoint: "/app/server", AllowedHosts: []string{"gmail.googleapis.com"},
		Injections: []store.Injection{{
			ID: "oauth", Type: "oauth2", Provider: "gmail", // no Vendor
			Scopes: []string{"email"}, Header: "Authorization",
			Format: "Bearer {token}", Placeholder: "PH",
		}},
		ManifestHash: "h1",
	}); err != nil {
		t.Fatal(err)
	}

	ens := &fakeEnsurer{token: "tok"}
	r := &CredResolver{Store: st, Broker: ens}
	if _, err := r.Resolve(proxy.Identity{Server: "gmail", Tenant: store.UserTenant(42)}, "gmail.googleapis.com"); err != nil {
		t.Fatal(err)
	}
	if ens.gotVendor != "gmail" {
		t.Fatalf("empty vendor must fall back to provider, got %q", ens.gotVendor)
	}
}
