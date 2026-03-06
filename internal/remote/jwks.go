package remote

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v3"
)

// LoadJWKS loads a JWKS from a remote URL or a local file path.
func LoadJWKS(source string) (*jose.JSONWebKeySet, error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		return fetchRemoteJWKS(source)
	}
	return loadLocalJWKS(source)
}

func fetchRemoteJWKS(url string) (*jose.JSONWebKeySet, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: status %d", url, resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS from %s: %w", url, err)
	}

	return &jwks, nil
}

func loadLocalJWKS(path string) (*jose.JSONWebKeySet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS file %s: %w", path, err)
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS from %s: %w", path, err)
	}

	return &jwks, nil
}
