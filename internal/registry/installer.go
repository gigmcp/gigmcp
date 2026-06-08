package registry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/gigmcp/gigmcp/internal/oci"
	"github.com/gigmcp/gigmcp/internal/store"
)

// uninstallNameRE mirrors the schema package's manifest-name rule; Uninstall
// takes a raw caller-supplied name (e.g. from the REST API), so it must be
// re-validated here before it reaches the filesystem glob.
var uninstallNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// IndexInstaller implements Installer against the signed registry index.
type IndexInstaller struct {
	Store   store.Store
	Client  *Client
	Puller  *oci.Puller
	DataDir string // extracted binaries land in <DataDir>/servers/<name>@<version>/server
	// AutoConsent records consent for an UPGRADE (a manifest whose hash differs
	// from the one the server was last consented to). Set for operator-initiated
	// boot installs (GIG_INSTALL), where the operator's deploy config is the
	// standing consent for whatever version the index resolves to.
	//
	// It does NOT govern first installs: an explicit install of a server that
	// has never been consented (admin POST /api/servers/install, or a boot
	// install) is itself the consent for that manifest, so consent is recorded
	// regardless of AutoConsent — otherwise an API-installed server could never
	// spawn (there is no separate consent endpoint). What stays gated behind
	// re-consent is a genuine manifest CHANGE to an already-consented server:
	// with AutoConsent=false (the API path) that leaves consented_hash stale so
	// the gateway's spawn path refuses the server until consent is re-recorded
	// (DESIGN #7).
	AutoConsent bool
}

var _ Installer = (*IndexInstaller)(nil)

func (i *IndexInstaller) Install(ctx context.Context, ref string) (store.Server, error) {
	ix, err := i.Client.FetchIndex(ctx)
	if err != nil {
		return store.Server{}, err
	}
	m, err := ix.Resolve(ref)
	if err != nil {
		return store.Server{}, err
	}
	// Defense in depth: a signed-but-malformed manifest must still not install.
	if err := m.Validate(); err != nil {
		return store.Server{}, fmt.Errorf("registry: manifest %s@%s invalid: %w", m.Name, m.Version, err)
	}
	hash, err := m.Hash()
	if err != nil {
		return store.Server{}, err
	}

	dest := filepath.Join(i.DataDir, "servers", m.Name+"@"+m.Version, "server")

	// Capture the pre-install consent state so the consent decision below can
	// distinguish a first-ever install (no prior consent ⇒ this install is the
	// consent) from an upgrade of an already-consented server (changed manifest
	// ⇒ re-consent, DESIGN #7).
	prior, priorErr := i.Store.GetManifest(ctx, m.Name)
	hadPrior := priorErr == nil
	if !hadPrior && !errors.Is(priorErr, store.ErrManifestNotFound) {
		return store.Server{}, priorErr
	}

	// Idempotent by (name, version, hash): same install → refresh, keep
	// placeholders untouched. Consent is still (re)applied: a first install
	// whose binary is already on disk must end up consented too.
	if hadPrior && prior.Version == m.Version && prior.ManifestHash == hash {
		if _, statErr := os.Stat(dest); statErr == nil {
			srv, err := i.Store.EnsureServer(ctx, m.Name, dest)
			if err != nil {
				return store.Server{}, err
			}
			if err := i.maybeConsent(ctx, m.Name, hash, prior, hadPrior); err != nil {
				return store.Server{}, err
			}
			return srv, nil
		}
	}

	if err := i.Puller.Extract(ctx, m.Image.Ref, m.Image.Digest, m.Image.Entrypoint, dest); err != nil {
		return store.Server{}, err
	}

	injections := make([]store.Injection, 0, len(m.Credentials))
	for _, c := range m.Credentials {
		ph, err := newPlaceholder()
		if err != nil {
			return store.Server{}, err
		}
		injections = append(injections, store.Injection{
			ID: c.ID, Header: c.Inject.Header, Format: c.Inject.Format,
			Env: c.Inject.Env, Placeholder: ph,
		})
	}
	tools := make([]store.ToolEntry, 0, len(m.Tools))
	for _, tl := range m.Tools {
		tools = append(tools, store.ToolEntry{Name: tl.Name, Default: tl.Default})
	}

	// Write manifest row FIRST. If the process dies between the two writes we
	// strand an inert manifest row (no server row → no spawn path). The inverse
	// ordering (server first) would leave an unguarded server row that the
	// legacy expose-all path could spawn.
	if err := i.Store.PutManifest(ctx, store.ManifestRecord{
		Server: m.Name, Version: m.Version, Digest: m.Image.Digest,
		Tier: m.Tier, Entrypoint: m.Image.Entrypoint,
		AllowedHosts: m.Entitlements.Egress,
		Injections:   injections, Tools: tools, ManifestHash: hash,
	}); err != nil {
		return store.Server{}, err
	}
	srv, err := i.Store.EnsureServer(ctx, m.Name, dest)
	if err != nil {
		return store.Server{}, err
	}
	if err := i.maybeConsent(ctx, m.Name, hash, prior, hadPrior); err != nil {
		return store.Server{}, err
	}
	return srv, nil
}

// maybeConsent records consent for the just-installed manifest hash when the
// install action is itself the consent:
//
//   - first install of a server (no prior consented manifest) — the explicit
//     install is the consent, so the server can spawn; this is true for both
//     boot and API installs, and is what makes a dashboard install usable, OR
//   - an operator boot install (AutoConsent), where the deploy config stands in
//     as consent for whatever version resolves — including upgrades.
//
// It deliberately does NOT record consent for an API-path upgrade that CHANGES
// an already-consented manifest: that leaves consented_hash stale so the
// spawn-side gate (ManifestRecord.NeedsReconsent) fails closed until the change
// is explicitly re-consented (DESIGN #7).
func (i *IndexInstaller) maybeConsent(ctx context.Context, name, hash string, prior store.ManifestRecord, hadPrior bool) error {
	firstConsent := !hadPrior || prior.ConsentedHash == ""
	if i.AutoConsent || firstConsent {
		return i.Store.RecordConsent(ctx, name, hash)
	}
	return nil
}

func (i *IndexInstaller) Uninstall(ctx context.Context, name string) error {
	if !uninstallNameRE.MatchString(name) {
		return fmt.Errorf("registry: invalid server name %q", name)
	}
	// Delete server row FIRST. If the process dies between the two deletes we
	// strand an inert manifest row (no server row → no spawn path). The inverse
	// ordering (manifest first) would leave a server row with a binary on disk
	// that the legacy expose-all path could spawn without any entitlement guard.
	if err := i.Store.DeleteServer(ctx, name); err != nil {
		return err
	}
	if err := i.Store.DeleteManifest(ctx, name); err != nil {
		return err
	}
	// name re-validated above, so the glob is meta-character-free.
	matches, err := filepath.Glob(filepath.Join(i.DataDir, "servers", name+"@*"))
	if err != nil {
		return err
	}
	var errs []error
	for _, d := range matches {
		errs = append(errs, os.RemoveAll(d))
	}
	return errors.Join(errs...)
}

func (i *IndexInstaller) List(ctx context.Context) ([]store.Server, error) {
	return i.Store.ListServers(ctx)
}

// newPlaceholder returns a high-entropy sentinel. The proxy matches it as a
// SUBSTRING of the header value (proxy.Credential), so it must be unguessable
// and collision-free — this replaces the hardcoded "PLACEHOLDER".
func newPlaceholder() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "gigph-" + hex.EncodeToString(b[:]), nil
}
