package keycloak

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"jwt-tool/pkg/models"
)

// FetchDiscoveryRaw fetches the raw OIDC discovery document.
func FetchDiscoveryRaw(baseURL, realm string) ([]byte, error) {
	url := constructDiscoveryURL(baseURL, realm)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("could not fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not fetch discovery document from %s: status %d", url, resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// FetchDiscovery fetches and parses the OIDC discovery document.
func FetchDiscovery(baseURL, realm string) (*models.KeycloakDiscovery, error) {
	data, err := FetchDiscoveryRaw(baseURL, realm)
	if err != nil {
		return nil, err
	}

	var discovery models.KeycloakDiscovery
	if err := json.Unmarshal(data, &discovery); err != nil {
		return nil, fmt.Errorf("could not decode discovery document: %w", err)
	}

	return &discovery, nil
}

func constructDiscoveryURL(baseURL, realm string) string {
	baseURL = strings.TrimSuffix(baseURL, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}
	return fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", baseURL, realm)
}
