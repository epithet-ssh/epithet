package main

// AuthCLI is the parent command for authentication-related subcommands.
type AuthCLI struct {
	OIDC AuthOIDCCLI `cmd:"oidc" help:"Authenticate using OIDC/OAuth2 (Google Workspace, Okta, Azure AD, etc.)"`
}
