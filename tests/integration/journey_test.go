package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestFullJourneyExhaustive(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		kgAlg   string
		kgArgs  []string
		signAlg string
	}{
		{kgAlg: "rsa", kgArgs: []string{"-b", "2048"}, signAlg: "RS256"},
		{kgAlg: "rsa", kgArgs: []string{"-b", "3072"}, signAlg: "RS384"},
		{kgAlg: "rsa", kgArgs: []string{"-b", "4096"}, signAlg: "RS512"},
		{kgAlg: "rsa", kgArgs: []string{"-b", "2048"}, signAlg: "PS256"},
		{kgAlg: "rsa", kgArgs: []string{"-b", "3072"}, signAlg: "PS384"},
		{kgAlg: "rsa", kgArgs: []string{"-b", "4096"}, signAlg: "PS512"},
		{kgAlg: "ecdsa", kgArgs: []string{"-c", "P256"}, signAlg: "ES256"},
		{kgAlg: "ecdsa", kgArgs: []string{"-c", "P384"}, signAlg: "ES384"},
		{kgAlg: "ecdsa", kgArgs: []string{"-c", "P521"}, signAlg: "ES512"},
		{kgAlg: "eddsa", kgArgs: []string{}, signAlg: "EdDSA"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.kgAlg, tt.signAlg), func(t *testing.T) {
			keyFile := filepath.Join(tmpDir, fmt.Sprintf("key_%s", tt.signAlg))
			pubFile := keyFile + ".pub"

			// 1. Keygen
			keygenArgs := append([]string{"keygen", "-a", tt.kgAlg, "-f", keyFile}, tt.kgArgs...)
			_, _, err := execute(keygenArgs...)
			if err != nil {
				t.Fatalf("keygen failed: %v", err)
			}

			// 2. Create with flags
			token1, _, err := execute("create", "--alg", tt.signAlg, "--pem", "@"+keyFile, "--sub", "user1", "--header", "kid=key1")
			if err != nil {
				t.Fatalf("create failed: %v", err)
			}

			// 3. Create with payload file
			payloadFile := filepath.Join(tmpDir, "payload_journey.json")
			payload := map[string]interface{}{"sub": "user2"}
			data, _ := json.Marshal(payload)
			if err := os.WriteFile(payloadFile, data, 0644); err != nil {
				t.Fatalf("failed to write payload file: %v", err)
			}

			token2, _, err := execute("create", "--alg", tt.signAlg, "--pem", "@"+keyFile, "--payload", "@"+payloadFile, "--header", "kid=key1")
			if err != nil {
				t.Fatalf("create with payload failed: %v", err)
			}

			// 4. JWKS
			jwksOut, _, err := execute("jwks", "@"+pubFile, "--kid", "key1")
			if err != nil {
				t.Fatalf("jwks failed: %v", err)
			}
			jwksFile := filepath.Join(tmpDir, "jwks.json")
			if err := os.WriteFile(jwksFile, []byte(jwksOut), 0644); err != nil {
				t.Fatalf("failed to write jwks file: %v", err)
			}

			// 5. Verify using JWKS
			for _, token := range []string{token1, token2} {
				out, _, err := execute("inspect", token, "--jwks", jwksFile)
				if err != nil {
					t.Fatalf("verify with jwks failed: %v", err)
				}
				info := parseTokenInfo(t, out)
				assertValidation(t, info, true, tt.signAlg)
			}

			// 6. Verify using PEM
			for _, token := range []string{token1, token2} {
				out, _, err := execute("inspect", token, "--pem", "@"+pubFile)
				if err != nil {
					t.Fatalf("verify with pem failed: %v", err)
				}
				info := parseTokenInfo(t, out)
				assertValidation(t, info, true, tt.signAlg)
			}
		})
	}
}
