package gateway

import (
	"context"
	"errors"

	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

// CredResolver implements proxy.CredentialResolver over the store + vault.
type CredResolver struct {
	Store store.Store
	Vault *vault.Vault
}

// Resolve assembles the proxy credential from TWO sources (DESIGN #7,
// seam §6.C): the MANIFEST (by server) supplies the author-declared hard cap
// — allowlist + injection schema + placeholder; the VAULT (by server,tenant)
// supplies only the real secret. Servers without a manifest (legacy
// GIG_ECHO_BIN seeding) fall back to the credential row's own fields.
func (c *CredResolver) Resolve(id proxy.Identity, host string) (proxy.Credential, error) {
	ctx := context.Background()
	cred, err := c.Store.GetCredential(ctx, id.Server, id.Tenant)
	if err != nil {
		return proxy.Credential{}, err
	}
	secret, err := c.Vault.Decrypt(cred.EncryptedKey)
	if err != nil {
		return proxy.Credential{}, err
	}
	rec, err := c.Store.GetManifest(ctx, id.Server)
	if errors.Is(err, store.ErrManifestNotFound) {
		return proxy.Credential{
			RealSecret:   string(secret),
			InjectHeader: cred.InjectHeader,
			InjectFormat: cred.InjectFormat,
			Placeholder:  cred.Placeholder,
			AllowedHosts: cred.AllowedHosts,
		}, nil
	}
	if err != nil {
		return proxy.Credential{}, err
	}
	// v1 enforces the FIRST credential's injection (multi-credential rewrite
	// is a follow-up; the schema already supports it).
	var inj store.Injection
	if len(rec.Injections) > 0 {
		inj = rec.Injections[0]
	}
	return proxy.Credential{
		RealSecret:   string(secret),
		InjectHeader: inj.Header,
		InjectFormat: inj.Format,
		Placeholder:  inj.Placeholder,
		AllowedHosts: rec.AllowedHosts,
	}, nil
}
