package keycloak

import (
	"jwt-tool/internal/oidc"
	"jwt-tool/pkg/models"
)

// LoginOptions holds parameters for the login request.
type LoginOptions struct {
	BaseURL      string
	Realm        string
	ClientID     string
	ClientSecret string
	Username     string
	Password     string
	Scope        string
}

// Login performs the token request and returns the parsed response.
func Login(opts LoginOptions) (*models.OIDCTokenResponse, error) {
	issuer := constructIssuerURL(opts.BaseURL, opts.Realm)
	return oidc.Login(oidc.LoginOptions{
		Issuer:       issuer,
		ClientID:     opts.ClientID,
		ClientSecret: opts.ClientSecret,
		Username:     opts.Username,
		Password:     opts.Password,
		Scope:        opts.Scope,
	})
}
