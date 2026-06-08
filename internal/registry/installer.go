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
	"github.com/gigmcp/registry/schema"
)

// builderToolpack is the image.builder discriminator that selects the multi-file
// bundle install path. Any other value (including "" / "go-static") uses the
// legacy single-file path unchanged.
const builderToolpack = "toolpack"

// ManifestMismatchError reports that the manifest.yaml baked into a toolpack
// image does not match the signed/consented index manifest for the same
// server@version. The image-index digest is pinned and signature-verified, so a
// mismatch means the image was tampered after signing (or the registry shipped
// an inconsistent bundle): the install is rejected so the tampered image never
// runs. It is surfaced through the install API so the dashboard shows a real
// message.
type ManifestMismatchError struct {
	Server      string
	Version     string
	IndexHash   string // hash of the consented/index manifest
	BundledHash string // hash of the manifest.yaml extracted from the image
}

func (e *ManifestMismatchError) Error() string {
	return fmt.Sprintf(
		"registry: toolpack %s@%s: bundled manifest.yaml does not match the signed index manifest (index hash %s, bundled %s); refusing to install a tampered image",
		e.Server, e.Version, e.IndexHash, e.BundledHash)
}

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

	bundle := m.Image.Builder == builderToolpack

	// stageDir is the per-server artifact directory under DataDir. For a
	// single-file server the entrypoint binary lands at <stageDir>/server; for a
	// toolpack bundle the whole flat bundle (server + sidecars) lands directly in
	// stageDir, which is later bind-mounted read-only at the in-image bundle path.
	stageDir := filepath.Join(i.DataDir, "servers", m.Name+"@"+m.Version)
	dest := filepath.Join(stageDir, "server")

	// Capture the pre-install consent state so the consent decision below can
	// distinguish a first-ever install (no prior consent ⇒ this install is the
	// consent) from an upgrade of an already-consented server (changed manifest
	// ⇒ re-consent, DESIGN #7).
	prior, priorErr := i.Store.GetManifest(ctx, m.Name)
	hadPrior := priorErr == nil
	if !hadPrior && !errors.Is(priorErr, store.ErrManifestNotFound) {
		return store.Server{}, priorErr
	}

	// ensureRow records the server row in the correct (bundle vs single-file)
	// mode. The entrypoint is always the exec target; for bundles bundle_dir is
	// the staging directory the gateway mounts.
	ensureRow := func() (store.Server, error) {
		if bundle {
			return i.Store.EnsureServerBundle(ctx, m.Name, m.Image.Entrypoint, stageDir)
		}
		return i.Store.EnsureServer(ctx, m.Name, dest)
	}

	// Idempotent by (name, version, hash): same install → refresh, keep
	// placeholders untouched. Consent is still (re)applied: a first install
	// whose artifact is already on disk must end up consented too.
	if hadPrior && prior.Version == m.Version && prior.ManifestHash == hash {
		if _, statErr := os.Stat(dest); statErr == nil {
			srv, err := ensureRow()
			if err != nil {
				return store.Server{}, err
			}
			if err := i.maybeConsent(ctx, m.Name, hash, prior, hadPrior); err != nil {
				return store.Server{}, err
			}
			return srv, nil
		}
	}

	if bundle {
		b, err := i.Puller.ExtractBundle(ctx, m.Image.Ref, m.Image.Digest, m.Image.Entrypoint, stageDir)
		if err != nil {
			return store.Server{}, err
		}
		// Defense in depth: the manifest.yaml baked into the image must equal the
		// signed/consented index manifest for this server@version. The image-index
		// digest is pinned+signature-verified, so a mismatch means a tampered
		// image — reject it (toolspec.yaml is NOT cross-checked; its integrity is
		// already covered by the pinned digest).
		if err := crossCheckBundledManifest(b.Dir, m); err != nil {
			os.RemoveAll(stageDir)
			return store.Server{}, err
		}
	} else if err := i.Puller.Extract(ctx, m.Image.Ref, m.Image.Digest, m.Image.Entrypoint, dest); err != nil {
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
	srv, err := ensureRow()
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

// crossCheckBundledManifest parses the manifest.yaml extracted from a toolpack
// image and asserts it is EQUAL to the signed/consented index manifest m.
//
// Both sides are reduced to the canonical manifest hash (schema.Manifest.Hash: a
// SHA-256 over canonical JSON of the parsed struct), which is robust to trailing
// whitespace and YAML formatting and ignores fields the schema does not model.
// The bundled manifest is re-parsed AND re-validated (a signed-but-malformed
// bundled manifest must still not install).
//
// Image.Digest is EXCLUDED from the comparison: it is the content-address of the
// image that contains manifest.yaml, so it cannot appear inside that file
// without being self-referential — the registry fills it into the index entry
// only after building the image. Its integrity is already covered by the pinned,
// signature-verified image-index digest, so comparing the rest of the structured
// manifest is the right defense-in-depth check. On any mismatch a
// *ManifestMismatchError is returned so the tampered image is rejected.
func crossCheckBundledManifest(bundleDir string, m *schema.Manifest) error {
	raw, err := os.ReadFile(filepath.Join(bundleDir, "manifest.yaml"))
	if err != nil {
		return fmt.Errorf("registry: read bundled manifest.yaml: %w", err)
	}
	bm, err := schema.Parse(raw)
	if err != nil {
		return fmt.Errorf("registry: parse bundled manifest.yaml: %w", err)
	}
	if err := bm.Validate(); err != nil {
		return fmt.Errorf("registry: bundled manifest.yaml invalid: %w", err)
	}
	wantHash, err := digestIndependentHash(m)
	if err != nil {
		return err
	}
	got, err := digestIndependentHash(bm)
	if err != nil {
		return err
	}
	if got != wantHash {
		return &ManifestMismatchError{
			Server: m.Name, Version: m.Version,
			IndexHash: wantHash, BundledHash: got,
		}
	}
	return nil
}

// digestIndependentHash hashes a manifest with Image.Digest cleared, so the
// cross-check compares author-declared content (name, version, tier, egress,
// credentials, tools, entrypoint, builder, ...) and not the self-referential
// image content-address. It copies the value so the caller's manifest is
// untouched.
func digestIndependentHash(m *schema.Manifest) (string, error) {
	c := *m
	c.Image.Digest = ""
	return c.Hash()
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
