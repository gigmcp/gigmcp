package gateway

import (
	"context"

	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

// CredResolver implements proxy.CredentialResolver over the store + vault.
type CredResolver struct {
	Store store.Store
	Vault *vault.Vault
}

// Resolve fetches and decrypts the credential for the identity.
func (c *CredResolver) Resolve(id proxy.Identity, host string) (proxy.Credential, error) {
	cred, err := c.Store.GetCredential(context.Background(), id.Server, id.Tenant)
	if err != nil {
		return proxy.Credential{}, err
	}
	secret, err := c.Vault.Decrypt(cred.EncryptedKey)
	if err != nil {
		return proxy.Credential{}, err
	}
	return proxy.Credential{
		RealSecret:   string(secret),
		InjectHeader: cred.InjectHeader,
		InjectFormat: cred.InjectFormat,
		Placeholder:  cred.Placeholder,
		AllowedHosts: cred.AllowedHosts,
	}, nil
}
