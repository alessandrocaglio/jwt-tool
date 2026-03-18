package keycloak

import (
	"jwt-tool/internal/oidc"
	"jwt-tool/pkg/models"
)

// IntrospectRaw performs the introspection and returns the raw JSON bytes.
func IntrospectRaw(baseURL, realm, clientID, clientSecret, token string) ([]byte, error) {
	issuer := constructIssuerURL(baseURL, realm)
	return oidc.IntrospectRaw(issuer, clientID, clientSecret, token)
}

// Introspect performs the introspection and returns a parsed response.
func Introspect(baseURL, realm, clientID, clientSecret, token string) (models.IntrospectionResponse, error) {
	issuer := constructIssuerURL(baseURL, realm)
	return oidc.Introspect(issuer, clientID, clientSecret, token)
}
