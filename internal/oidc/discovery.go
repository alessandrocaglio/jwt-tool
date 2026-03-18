package oidc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"jwt-tool/pkg/models"
)

var (
	discoveryCache = make(map[string]*models.OIDCDiscovery)
	cacheMutex     sync.RWMutex
)

// FetchDiscoveryRaw fetches the raw OIDC discovery document from the issuer.
func FetchDiscoveryRaw(issuer string) ([]byte, error) {
	url := constructDiscoveryURL(issuer)
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

// FetchDiscovery fetches and parses the OIDC discovery document from the issuer.
func FetchDiscovery(issuer string) (*models.OIDCDiscovery, error) {
	cacheMutex.RLock()
	if cached, ok := discoveryCache[issuer]; ok {
		cacheMutex.RUnlock()
		return cached, nil
	}
	cacheMutex.RUnlock()

	data, err := FetchDiscoveryRaw(issuer)
	if err != nil {
		return nil, err
	}

	var discovery models.OIDCDiscovery
	if err := json.Unmarshal(data, &discovery); err != nil {
		return nil, fmt.Errorf("could not decode discovery document: %w", err)
	}

	cacheMutex.Lock()
	discoveryCache[issuer] = &discovery
	cacheMutex.Unlock()

	return &discovery, nil
}

func constructDiscoveryURL(issuer string) string {
	issuer = strings.TrimSuffix(issuer, "/")
	if !strings.HasPrefix(issuer, "http://") && !strings.HasPrefix(issuer, "https://") {
		issuer = "https://" + issuer
	}
	return fmt.Sprintf("%s/.well-known/openid-configuration", issuer)
}
