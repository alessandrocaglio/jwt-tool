package keycloak

import (
	"fmt"
	"strings"

	"jwt-tool/internal/oidc"
	"jwt-tool/pkg/models"
)

// FetchDiscoveryRaw fetches the raw OIDC discovery document for a Keycloak realm.
func FetchDiscoveryRaw(baseURL, realm string) ([]byte, error) {
	issuer := constructIssuerURL(baseURL, realm)
	return oidc.FetchDiscoveryRaw(issuer)
}

// FetchDiscovery fetches and parses the OIDC discovery document for a Keycloak realm.
func FetchDiscovery(baseURL, realm string) (*models.OIDCDiscovery, error) {
	issuer := constructIssuerURL(baseURL, realm)
	return oidc.FetchDiscovery(issuer)
}

func constructIssuerURL(baseURL, realm string) string {
	baseURL = strings.TrimSuffix(baseURL, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}
	return fmt.Sprintf("%s/realms/%s", baseURL, realm)
}
