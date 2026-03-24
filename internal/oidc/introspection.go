package oidc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"jawt/pkg/models"
)

// IntrospectRaw performs the introspection and returns the raw JSON bytes.
func IntrospectRaw(issuer, clientID, clientSecret, token string) ([]byte, error) {
	discovery, err := FetchDiscovery(issuer)
	if err != nil {
		return nil, fmt.Errorf("could not discover introspection endpoint: %w", err)
	}

	if discovery.IntrospectionEndpoint == "" {
		return nil, fmt.Errorf("introspection endpoint not found in discovery document")
	}

	data := url.Values{}
	data.Set("token", token)
	data.Set("token_type_hint", "access_token")

	req, err := http.NewRequest("POST", discovery.IntrospectionEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("could not create introspection request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not send introspection request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection request failed with status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// Introspect performs the introspection and returns a parsed response.
func Introspect(issuer, clientID, clientSecret, token string) (models.IntrospectionResponse, error) {
	raw, err := IntrospectRaw(issuer, clientID, clientSecret, token)
	if err != nil {
		return nil, err
	}

	var response models.IntrospectionResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, fmt.Errorf("could not decode introspection response: %w", err)
	}

	return response, nil
}
