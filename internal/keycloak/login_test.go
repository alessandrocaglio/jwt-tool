package keycloak

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Handle Discovery Request
		if r.URL.Path == "/realms/test-realm/.well-known/openid-configuration" {
			fmt.Fprintf(w, `{"token_endpoint": "%s/token"}`, "http://"+r.Host)
			return
		}

		// Handle Token Request
		if r.URL.Path == "/token" {
			if err := r.ParseForm(); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Verify Client Credentials
			if r.FormValue("client_id") != "client-id" || r.FormValue("client_secret") != "client-secret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			grantType := r.FormValue("grant_type")
			if grantType == "client_credentials" {
				fmt.Fprint(w, `{"access_token": "cc-token", "expires_in": 300, "token_type": "Bearer"}`)
				return
			} else if grantType == "password" {
				if r.FormValue("username") == "user" && r.FormValue("password") == "pass" {
					fmt.Fprint(w, `{"access_token": "pw-token", "refresh_token": "refresh-token", "expires_in": 300, "token_type": "Bearer"}`)
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	t.Run("Client Credentials", func(t *testing.T) {
		resp, err := Login(LoginOptions{
			BaseURL:      server.URL,
			Realm:        "test-realm",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
		})
		if err != nil {
			t.Fatalf("Login() error = %v", err)
		}
		if resp.AccessToken != "cc-token" {
			t.Errorf("got %v, want cc-token", resp.AccessToken)
		}
	})

	t.Run("Password Grant", func(t *testing.T) {
		resp, err := Login(LoginOptions{
			BaseURL:      server.URL,
			Realm:        "test-realm",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			Username:     "user",
			Password:     "pass",
		})
		if err != nil {
			t.Fatalf("Login() error = %v", err)
		}
		if resp.AccessToken != "pw-token" {
			t.Errorf("got %v, want pw-token", resp.AccessToken)
		}
		if resp.RefreshToken != "refresh-token" {
			t.Errorf("got %v, want refresh-token", resp.RefreshToken)
		}
	})
}
