package auth

// VendorSeed is the canonical (operator-credential-free) OAuth endpoint set for
// a managed vendor. Client credentials are supplied by the operator (managed:
// our verified app; byo: the self-hoster's) and are NEVER in this table — only
// the public authorize/token endpoints + recommended default scopes + PKCE.
type VendorSeed struct {
	Vendor        string
	AuthorizeURL  string
	TokenURL      string
	DefaultScopes []string
	PKCE          bool
	Mode          string // always "managed" for seeds
}

// ManagedVendorSeeds returns the canonical endpoint rows for the top managed
// vendors (spec §1: Google/Microsoft/Slack/Atlassian/Zoho/Meta cover the bulk
// of OAuth connectors). Operators supply client_id/client_secret per vendor.
func ManagedVendorSeeds() map[string]VendorSeed {
	return map[string]VendorSeed{
		"google": {
			Vendor: "google", Mode: "managed", PKCE: true,
			AuthorizeURL:  "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:      "https://oauth2.googleapis.com/token",
			DefaultScopes: []string{"openid", "email", "profile"},
		},
		"microsoft": {
			Vendor: "microsoft", Mode: "managed", PKCE: true,
			AuthorizeURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			TokenURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			DefaultScopes: []string{"openid", "email", "profile", "offline_access"},
		},
		"slack": {
			Vendor: "slack", Mode: "managed", PKCE: false,
			AuthorizeURL:  "https://slack.com/oauth/v2/authorize",
			TokenURL:      "https://slack.com/api/oauth.v2.access",
			DefaultScopes: nil,
		},
		"atlassian": {
			Vendor: "atlassian", Mode: "managed", PKCE: true,
			AuthorizeURL:  "https://auth.atlassian.com/authorize",
			TokenURL:      "https://auth.atlassian.com/oauth/token",
			DefaultScopes: []string{"offline_access"},
		},
		"zoho": {
			Vendor: "zoho", Mode: "managed", PKCE: false,
			AuthorizeURL:  "https://accounts.zoho.com/oauth/v2/auth",
			TokenURL:      "https://accounts.zoho.com/oauth/v2/token",
			DefaultScopes: nil,
		},
		"notion": {
			Vendor: "notion", Mode: "managed", PKCE: false,
			AuthorizeURL:  "https://api.notion.com/v1/oauth/authorize",
			TokenURL:      "https://api.notion.com/v1/oauth/token",
			DefaultScopes: nil,
		},
	}
}
