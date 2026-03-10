package models

// KeycloakDiscovery represents the OIDC discovery document.
type KeycloakDiscovery struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	CheckSessionIframe                string   `json:"check_session_iframe"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// IntrospectionResponse represents the exact response from the introspection endpoint.
// We use map[string]interface{} to preserve all fields for the JSON output.
type IntrospectionResponse map[string]interface{}

// IsActive returns the 'active' status of the token.
func (ir IntrospectionResponse) IsActive() bool {
	if active, ok := ir["active"].(bool); ok {
		return active
	}
	return false
}

// TokenResponse represents the standard OIDC token response.
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}
