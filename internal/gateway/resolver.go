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

// TokenEnsurer returns a currently-valid OAuth access token for (user, vendor),
// refreshing if needed. Implemented by *auth.OAuthBroker; nil disables the
// oauth2 resolver branch (api-key/none paths are unaffected).
type TokenEnsurer interface {
	EnsureFreshToken(ctx context.Context, userID int64, vendor string) (string, error)
}

// CredResolver implements proxy.CredentialResolver over the store + vault.
type CredResolver struct {
	Store  store.Store
	Vault  *vault.Vault
	Broker TokenEnsurer // nil = oauth2 apps fall through to the no-credential path
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

	// OAuth2 branch: if the manifest's first credential is oauth2, the secret
	// is the user's CURRENT vendor access token (refreshed at resolve time),
	// not a static stored credential. This runs before the credential lookup
	// so an oauth2 app with no `credentials` row still gets a bearer.
	if c.Broker != nil {
		if rec, err := c.Store.GetManifest(ctx, id.Server); err == nil &&
			len(rec.Injections) > 0 && rec.Injections[0].Type == "oauth2" {
			inj := rec.Injections[0]
			userID, perr := strconv.ParseInt(tenant, 10, 64)
			if perr != nil {
				// Non-numeric tenant (legacy "default") can't own an OAuth
				// connection; fall through to the no-credential path.
			} else {
				// Key the per-vendor connected account off the canonical signed
				// vendor (e.g. "google" for gmail/calendar/drive). Fall back to the
				// per-connector provider slug for un-backfilled manifests.
				vendor := inj.Vendor
				if vendor == "" {
					vendor = inj.Provider
				}
				token, terr := c.Broker.EnsureFreshToken(ctx, userID, vendor)
				if terr != nil {
					if errors.Is(terr, store.ErrConnectedAccountNotFound) {
						// Not connected yet: no bearer. Still grant entitled
						// egress (the app may call public endpoints) — same as
						// the credential-less manifest path. The injection guard
						// in the proxy skips injection when RealSecret/Placeholder
						// are present but the sandbox never sent the placeholder.
						return proxy.Credential{
							RealSecret: "", InjectHeader: "", InjectFormat: "",
							Placeholder: "", AllowedHosts: rec.AllowedHosts,
						}, nil
					}
					return proxy.Credential{}, terr
				}
				return proxy.Credential{
					RealSecret:   token,
					InjectHeader: inj.Header,
					InjectFormat: inj.Format,
					Placeholder:  inj.Placeholder,
					AllowedHosts: rec.AllowedHosts,
				}, nil
			}
		}
	}

	// The credential is OPTIONAL: a "sealed" server fronting a public API
	// (e.g. hackernews) has a manifest record — and therefore an entitled
	// allowlist — but NO secret to inject. Such a server must still get egress
	// to its entitled hosts. We branch on the not-found sentinel rather than
	// failing closed the moment a secret is absent.
	cred, credErr := c.Store.GetCredential(ctx, id.Server, tenant)
	credMissing := errors.Is(credErr, store.ErrCredentialNotFound)
	if credErr != nil && !credMissing {
		// A real store failure (not a clean "no such row") still propagates.
		return proxy.Credential{}, credErr
	}

	if credMissing {
		// No secret. The only legitimate egress source left is the manifest's
		// entitled allowlist. If there is also no manifest record, the server
		// is genuinely unknown/unconfigured — preserve fail-closed behaviour.
		rec, err := c.Store.GetManifest(ctx, id.Server)
		if err != nil {
			// Includes store.ErrManifestNotFound: unknown server → return the
			// original credential-not-found error (callers/audit treat it as
			// the no-credential case it is).
			if errors.Is(err, store.ErrManifestNotFound) {
				return proxy.Credential{}, credErr
			}
			return proxy.Credential{}, err
		}
		// Manifest record but no credential: egress to entitled hosts only,
		// nothing injected. Empty RealSecret/InjectHeader/Placeholder are safe
		// — the proxy skips injection when those are empty.
		return proxy.Credential{
			RealSecret:   "",
			InjectHeader: "",
			InjectFormat: "",
			Placeholder:  "",
			AllowedHosts: rec.AllowedHosts,
		}, nil
	}

	// A credential exists → behave exactly as before.
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
