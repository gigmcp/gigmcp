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
	// AutoConsent records consent at install time. Set for operator-initiated
	// boot installs (GIG_INSTALL); leave false for API installs, which keep
	// consented_hash empty so the gateway's spawn path refuses the server
	// until consent is recorded via store.RecordConsent (DESIGN #7).
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

	// Idempotent by (name, version, hash): same install → refresh, keep
	// placeholders and consent untouched.
	if existing, err := i.Store.GetManifest(ctx, m.Name); err == nil &&
		existing.Version == m.Version && existing.ManifestHash == hash {
		if _, statErr := os.Stat(dest); statErr == nil {
			return i.Store.EnsureServer(ctx, m.Name, dest)
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
	if i.AutoConsent {
		if err := i.Store.RecordConsent(ctx, m.Name, hash); err != nil {
			return store.Server{}, err
		}
	}
	return srv, nil
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
