package jwks

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestGenerateJWKS(t *testing.T) {
	// Generate a dummy RSA key
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaPub := rsaPriv.Public()

	// Generate a dummy Ed25519 key
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)

	pubKeys := []interface{}{rsaPub, edPub}
	kids := []string{"rsa-1", "ed-1"}

	jwks, err := GenerateJWKS(pubKeys, kids)
	if err != nil {
		t.Fatalf("Failed to generate JWKS: %v", err)
	}

	if len(jwks.Keys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(jwks.Keys))
	}

	if jwks.Keys[0].KeyID != "rsa-1" {
		t.Errorf("Expected kid rsa-1, got %s", jwks.Keys[0].KeyID)
	}

	if jwks.Keys[1].KeyID != "ed-1" {
		t.Errorf("Expected kid ed-1, got %s", jwks.Keys[1].KeyID)
	}

	for i, key := range jwks.Keys {
		if key.Use != "sig" {
			t.Errorf("Key %d: expected use sig, got %s", i, key.Use)
		}
	}
}

func TestGenerateJWKS_NoKids(t *testing.T) {
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	pubKeys := []interface{}{edPub}

	jwks, err := GenerateJWKS(pubKeys, nil)
	if err != nil {
		t.Fatalf("Failed to generate JWKS: %v", err)
	}

	if len(jwks.Keys) != 1 {
		t.Errorf("Expected 1 key, got %d", len(jwks.Keys))
	}

	if jwks.Keys[0].KeyID != "" {
		t.Errorf("Expected empty kid, got %s", jwks.Keys[0].KeyID)
	}
}

func TestGenerateJWKS_InvalidKey(t *testing.T) {
	pubKeys := []interface{}{"not-a-key"}
	_, err := GenerateJWKS(pubKeys, nil)
	if err == nil {
		t.Error("Expected error for invalid key, got nil")
	}
}
