package keycloak

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConstructDiscoveryURL(t *testing.T) {
	tests := []struct {
		baseURL  string
		realm    string
		expected string
	}{
		{"http://localhost:8080", "master", "http://localhost:8080/realms/master/.well-known/openid-configuration"},
		{"https://auth.example.com/", "myrealm", "https://auth.example.com/realms/myrealm/.well-known/openid-configuration"},
		{"auth.example.com", "myrealm", "https://auth.example.com/realms/myrealm/.well-known/openid-configuration"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s", tt.baseURL, tt.realm), func(t *testing.T) {
			got := constructDiscoveryURL(tt.baseURL, tt.realm)
			if got != tt.expected {
				t.Errorf("constructDiscoveryURL() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestFetchDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/realms/test-realm/.well-known/openid-configuration" {
			t.Errorf("expected path /realms/test-realm/.well-known/openid-configuration, got %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"issuer": "http://test-issuer", "jwks_uri": "http://test-issuer/jwks"}`)
	}))
	defer server.Close()

	discovery, err := FetchDiscovery(server.URL, "test-realm")
	if err != nil {
		t.Fatalf("FetchDiscovery() error = %v", err)
	}

	if discovery.Issuer != "http://test-issuer" {
		t.Errorf("discovery.Issuer = %v, want %v", discovery.Issuer, "http://test-issuer")
	}
	if discovery.JwksURI != "http://test-issuer/jwks" {
		t.Errorf("discovery.JwksURI = %v, want %v", discovery.JwksURI, "http://test-issuer/jwks")
	}
}

func TestFetchDiscoveryRaw(t *testing.T) {
	expectedData := `{"issuer": "http://test-issuer"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, expectedData)
	}))
	defer server.Close()

	data, err := FetchDiscoveryRaw(server.URL, "test-realm")
	if err != nil {
		t.Fatalf("FetchDiscoveryRaw() error = %v", err)
	}

	if string(data) != expectedData {
		t.Errorf("FetchDiscoveryRaw() data = %v, want %v", string(data), expectedData)
	}
}
