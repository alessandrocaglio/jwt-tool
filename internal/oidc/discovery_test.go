package oidc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConstructDiscoveryURL(t *testing.T) {
	tests := []struct {
		issuer   string
		expected string
	}{
		{"http://localhost:8080", "http://localhost:8080/.well-known/openid-configuration"},
		{"https://auth.example.com/", "https://auth.example.com/.well-known/openid-configuration"},
		{"auth.example.com", "https://auth.example.com/.well-known/openid-configuration"},
	}

	for _, tt := range tests {
		t.Run(tt.issuer, func(t *testing.T) {
			got := constructDiscoveryURL(tt.issuer)
			if got != tt.expected {
				t.Errorf("constructDiscoveryURL() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestFetchDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Errorf("expected path /.well-known/openid-configuration, got %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"issuer": "http://test-issuer", "jwks_uri": "http://test-issuer/jwks"}`)
	}))
	defer server.Close()

	discovery, err := FetchDiscovery(server.URL)
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

	data, err := FetchDiscoveryRaw(server.URL)
	if err != nil {
		t.Fatalf("FetchDiscoveryRaw() error = %v", err)
	}

	if string(data) != expectedData {
		t.Errorf("FetchDiscoveryRaw() data = %v, want %v", string(data), expectedData)
	}
}

func TestFetchDiscovery_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"issuer": "http://test-issuer", "jwks_uri": "http://test-issuer/jwks"`)
	}))
	defer server.Close()

	_, err := FetchDiscovery(server.URL)
	if err == nil {
		t.Fatal("FetchDiscovery() error = nil, want error")
	}
}
