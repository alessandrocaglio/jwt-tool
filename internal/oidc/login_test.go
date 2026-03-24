package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"jawt/pkg/models"
)

func TestLogin(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"issuer": "http://test-issuer", "token_endpoint": "`+server.URL+`/token"}`)
			return
		}

		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			response := models.OIDCTokenResponse{
				AccessToken: "test-access-token",
				ExpiresIn:   3600,
				TokenType:   "Bearer",
			}
			err := json.NewEncoder(w).Encode(response)
			if err != nil {
				t.Fatalf("could not encode response: %v", err)
			}
			return
		}

		t.Errorf("unexpected path: %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	opts := LoginOptions{
		Issuer:       server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	response, err := Login(opts)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	expected := &models.OIDCTokenResponse{
		AccessToken: "test-access-token",
		ExpiresIn:   3600,
		TokenType:   "Bearer",
	}

	if !reflect.DeepEqual(response, expected) {
		t.Errorf("Login() = %v, want %v", response, expected)
	}
}

func TestLogin_WithPasswordGrant(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"issuer": "http://test-issuer", "token_endpoint": "`+server.URL+`/token"}`)
			return
		}

		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			response := models.OIDCTokenResponse{
				AccessToken: "test-access-token-password",
				ExpiresIn:   3600,
				TokenType:   "Bearer",
			}
			err := json.NewEncoder(w).Encode(response)
			if err != nil {
				t.Fatalf("could not encode response: %v", err)
			}
			return
		}

		t.Errorf("unexpected path: %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	opts := LoginOptions{
		Issuer:       server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Username:     "test-user",
		Password:     "test-password",
	}

	response, err := Login(opts)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	expected := &models.OIDCTokenResponse{
		AccessToken: "test-access-token-password",
		ExpiresIn:   3600,
		TokenType:   "Bearer",
	}

	if !reflect.DeepEqual(response, expected) {
		t.Errorf("Login() = %v, want %v", response, expected)
	}
}
