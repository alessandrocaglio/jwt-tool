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

func TestIntrospect(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"issuer": "http://test-issuer", "introspection_endpoint": "`+server.URL+`/introspect"}`)
			return
		}

		if r.URL.Path == "/introspect" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"active": true, "sub": "test-sub"}`)
			return
		}

		t.Errorf("unexpected path: %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	response, err := Introspect(server.URL, "test-client", "test-secret", "test-token")
	if err != nil {
		t.Fatalf("Introspect() error = %v", err)
	}

	expected := models.IntrospectionResponse{"active": true, "sub": "test-sub"}
	if !reflect.DeepEqual(response, expected) {
		t.Errorf("Introspect() = %v, want %v", response, expected)
	}
}

func TestIntrospectRaw(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"issuer": "http://test-issuer", "introspection_endpoint": "`+server.URL+`/introspect"}`)
			return
		}

		if r.URL.Path == "/introspect" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"active": true, "sub": "test-sub"}`)
			return
		}

		t.Errorf("unexpected path: %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	raw, err := IntrospectRaw(server.URL, "test-client", "test-secret", "test-token")
	if err != nil {
		t.Fatalf("IntrospectRaw() error = %v", err)
	}

	var response models.IntrospectionResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatalf("could not unmarshal raw response: %v", err)
	}

	expected := models.IntrospectionResponse{"active": true, "sub": "test-sub"}
	if !reflect.DeepEqual(response, expected) {
		t.Errorf("IntrospectRaw() = %v, want %v", response, expected)
	}
}
