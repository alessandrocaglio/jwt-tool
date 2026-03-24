package keycloak

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"jawt/pkg/models"
)

func TestIntrospect(t *testing.T) {
	// 1. Mock Keycloak Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Handle Discovery Request
		if r.URL.Path == "/realms/test-realm/.well-known/openid-configuration" {
			fmt.Fprintf(w, `{"introspection_endpoint": "%s/introspect"}`, "http://"+r.Host)
			return
		}

		// Handle Introspection Request
		if r.URL.Path == "/introspect" {
			// Check Auth
			username, password, ok := r.BasicAuth()
			if !ok || username != "client-id" || password != "client-secret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// Check Body
			if err := r.ParseForm(); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if r.FormValue("token") != "test-token" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			fmt.Fprint(w, `{"active": true, "username": "testuser"}`)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// 2. Run Test
	resp, err := Introspect(server.URL, "test-realm", "client-id", "client-secret", "test-token")
	if err != nil {
		t.Fatalf("Introspect() error = %v", err)
	}

	if !resp.IsActive() {
		t.Errorf("resp.IsActive() = false, want true")
	}

	if resp["username"] != "testuser" {
		t.Errorf("resp['username'] = %v, want testuser", resp["username"])
	}
}

func TestIntrospectRaw(t *testing.T) {
	expectedData := `{"active":false}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/realms/test-realm/.well-known/openid-configuration" {
			fmt.Fprintf(w, `{"introspection_endpoint": "%s/introspect"}`, "http://"+r.Host)
			return
		}
		fmt.Fprint(w, expectedData)
	}))
	defer server.Close()

	data, err := IntrospectRaw(server.URL, "test-realm", "id", "secret", "token")
	if err != nil {
		t.Fatalf("IntrospectRaw() error = %v", err)
	}

	if string(data) != expectedData {
		t.Errorf("IntrospectRaw() data = %v, want %v", string(data), expectedData)
	}
}

func TestIntrospectionResponse_IsActive(t *testing.T) {
	tests := []struct {
		data     string
		expected bool
	}{
		{`{"active": true}`, true},
		{`{"active": false}`, false},
		{`{"other": "field"}`, false},
	}

	for _, tt := range tests {
		var resp map[string]interface{}
		if err := json.Unmarshal([]byte(tt.data), &resp); err != nil {
			t.Fatalf("failed to unmarshal test data %s: %v", tt.data, err)
		}
		ir := models.IntrospectionResponse(resp)
		if ir.IsActive() != tt.expected {
			t.Errorf("IsActive() for %s = %v, want %v", tt.data, ir.IsActive(), tt.expected)
		}
	}
}
