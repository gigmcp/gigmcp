package gateway

import (
	"context"
	"errors"
	"strconv"

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
//
// Tenant join (spec §6, this plan): if id.Tenant parses as an int64 AND
// names an existing profile, the credential lookup uses the profile OWNER's
// user id as a decimal string (credentials are per-user; one key serves all
// of that user's profiles). Otherwise the tenant is used literally — this
// keeps the legacy "default" tenant working until cutover.
func (c *CredResolver) Resolve(id proxy.Identity, host string) (proxy.Credential, error) {
	ctx := context.Background()

	// Tenant join: numeric tenant → profile lookup → owner's user id.
	tenant := id.Tenant
	if pid, err := strconv.ParseInt(id.Tenant, 10, 64); err == nil {
		if p, perr := c.Store.GetProfileByID(ctx, pid); perr == nil {
			tenant = store.UserTenant(p.UserID)
		}
	}

	cred, err := c.Store.GetCredential(ctx, id.Server, tenant)
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
