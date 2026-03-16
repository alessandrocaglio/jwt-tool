package remote

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3"
)

func TestLoadLocalJWKS(t *testing.T) {
	reader := rand.Reader
	bitSize := 2048
	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		t.Fatal(err)
	}

	keySet := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: key.Public(), KeyID: "test-key", Use: "sig", Algorithm: "RS256"},
		},
	}
	data, err := json.Marshal(keySet)
	if err != nil {
		t.Fatal(err)
	}

	tmpFile, err := os.CreateTemp("", "jwks-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	t.Run("Valid local JWKS", func(t *testing.T) {
		jwks, err := loadLocalJWKS(tmpFile.Name())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(jwks.Keys) != 1 || jwks.Keys[0].KeyID != "test-key" {
			t.Errorf("got unexpected JWKS content: %+v", jwks)
		}
	})

	t.Run("Invalid path", func(t *testing.T) {
		_, err := loadLocalJWKS("non-existent.json")
		if err == nil {
			t.Error("expected error for non-existent file, got nil")
		}
	})
}

func TestFetchRemoteJWKS(t *testing.T) {
	reader := rand.Reader
	bitSize := 2048
	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		t.Fatal(err)
	}

	keySet := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: key.Public(), KeyID: "remote-key", Use: "sig", Algorithm: "RS256"},
		},
	}
	data, err := json.Marshal(keySet)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(data); err != nil {
			// In a test handler, we can just return or log
			return
		}
	}))
	defer server.Close()

	t.Run("Valid remote JWKS", func(t *testing.T) {
		jwks, err := fetchRemoteJWKS(server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(jwks.Keys) != 1 || jwks.Keys[0].KeyID != "remote-key" {
			t.Errorf("got unexpected JWKS content: %+v", jwks)
		}
	})

	t.Run("Remote error status", func(t *testing.T) {
		errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer errServer.Close()

		_, err := fetchRemoteJWKS(errServer.URL)
		if err == nil {
			t.Error("expected error for 500 status, got nil")
		}
	})
}

func TestLoadJWKSDispatcher(t *testing.T) {
	t.Run("Dispatcher identifies URL", func(t *testing.T) {
		_, err := LoadJWKS("http://invalid.url/jwks.json")
		if err == nil {
			t.Error("expected error for invalid URL")
		}
		if !strings.Contains(err.Error(), "could not fetch JWKS") {
			t.Errorf("expected fetch error, got: %v", err)
		}
	})

	t.Run("Dispatcher identifies local file", func(t *testing.T) {
		_, err := LoadJWKS("some-local-file.json")
		if err == nil {
			t.Error("expected error for non-existent local file")
		}
		if !strings.Contains(err.Error(), "could not read JWKS file") {
			t.Errorf("expected read error, got: %v", err)
		}
	})
}
