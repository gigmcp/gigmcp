package gateway

import (
	"context"
	"errors"
	"strconv"

	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

// resolveTenant resolves a raw tenant string to the canonical credential
// tenant, optionally returning the profile ID and owner user ID when the
// tenant names an existing profile.
//
// If tenant parses as an int64 AND GetProfileByID succeeds, returns
// (store.UserTenant(owner), &profileID, &ownerID). Otherwise returns
// (tenant, nil, nil) — covering both the "default" literal and numeric
// strings that do not correspond to a known profile.
//
// This helper is shared by CredResolver.Resolve and the AuditingResolver
// writer goroutine so the join logic cannot drift between the two callers
// (T15 will add a third caller when ProfileHost lands).
func resolveTenant(ctx context.Context, st store.Store, tenant string) (credTenant string, profileID, userID *int64) {
	if pid, err := strconv.ParseInt(tenant, 10, 64); err == nil {
		if p, perr := st.GetProfileByID(ctx, pid); perr == nil {
			id := pid
			uid := p.UserID
			return store.UserTenant(p.UserID), &id, &uid
		}
	}
	return tenant, nil, nil
}

// CredResolver implements proxy.CredentialResolver over the store + vault.
type CredResolver struct {
	Store store.Store
	Vault *vault.Vault
}

// Resolve assembles the proxy credential from TWO sources (DESIGN #7):
// the MANIFEST (by server) supplies the author-declared hard cap
// — allowlist + injection schema + placeholder; the VAULT (by server,tenant)
// supplies only the real secret. Servers without a manifest (legacy
// GIG_ECHO_BIN seeding) fall back to the credential row's own fields.
//
// Tenant join: if id.Tenant parses as an int64 AND
// names an existing profile, the credential lookup uses the profile OWNER's
// user id as a decimal string (credentials are per-user; one key serves all
// of that user's profiles). Otherwise the tenant is used literally — this
// keeps the legacy "default" tenant working until cutover.
//
// Called once per MCP CONNECT (not per request), so the GetProfileByID read
// inside resolveTenant is fine uncached — it is a one-time handshake cost.
func (c *CredResolver) Resolve(id proxy.Identity, host string) (proxy.Credential, error) {
	ctx := context.Background()

	// Tenant join: numeric tenant → profile lookup → owner's user id.
	tenant, _, _ := resolveTenant(ctx, c.Store, id.Tenant)

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
	// The FIRST credential's injection is enforced (multi-credential rewrite
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
