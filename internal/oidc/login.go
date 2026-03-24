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

// LoginOptions holds parameters for the login request.
type LoginOptions struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Username     string
	Password     string
	Scope        string
}

// Login performs the token request and returns the parsed response.
func Login(opts LoginOptions) (*models.OIDCTokenResponse, error) {
	discovery, err := FetchDiscovery(opts.Issuer)
	if err != nil {
		return nil, fmt.Errorf("could not discover token endpoint: %w", err)
	}

	if discovery.TokenEndpoint == "" {
		return nil, fmt.Errorf("token endpoint not found in discovery document")
	}

	data := url.Values{}
	data.Set("client_id", opts.ClientID)
	data.Set("client_secret", opts.ClientSecret)

	if opts.Username != "" {
		data.Set("grant_type", "password")
		data.Set("username", opts.Username)
		data.Set("password", opts.Password)
	} else {
		data.Set("grant_type", "client_credentials")
	}

	if opts.Scope != "" {
		data.Set("scope", opts.Scope)
	}

	req, err := http.NewRequest("POST", discovery.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("could not create login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not send login request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read login response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("login failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp models.OIDCTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("could not decode login response: %w", err)
	}

	return &tokenResp, nil
}
