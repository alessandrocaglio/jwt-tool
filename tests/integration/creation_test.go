package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTokenCreation(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("HMAC", func(t *testing.T) {
		tests := []struct {
			name string
			args []string
			sub  string
		}{
			{
				name: "HS256 with flags",
				args: []string{"create", "--alg", "HS256", "--secret", "secret", "--sub", "user123"},
				sub:  "user123",
			},
			{
				name: "Sign alias",
				args: []string{"sign", "--alg", "HS256", "--secret", "secret", "--sub", "alias-user"},
				sub:  "alias-user",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				out, _, err := execute(tt.args...)
				if err != nil {
					t.Fatalf("failed to create token: %v", err)
				}

				// Verify by inspecting
				inspectOut, _, err := execute("inspect", out, "--secret", "secret")
				if err != nil {
					t.Fatalf("failed to inspect token: %v", err)
				}

				info := parseTokenInfo(t, inspectOut)
				assertValidation(t, info, true, "HS256")
				if info.Payload["sub"] != tt.sub {
					t.Errorf("expected sub %s, got %v", tt.sub, info.Payload["sub"])
				}
			})
		}
	})

	t.Run("Asymmetric", func(t *testing.T) {
		keyFile := filepath.Join(tmpDir, "rsa_key")
		_, _, err := execute("keygen", "-a", "rsa", "-f", keyFile)
		if err != nil {
			t.Fatalf("keygen failed: %v", err)
		}

		out, _, err := execute("create", "--alg", "RS256", "--pem", "@"+keyFile, "--sub", "rsa-user")
		if err != nil {
			t.Fatalf("create failed: %v", err)
		}

		inspectOut, _, err := execute("inspect", out, "--pem", "@"+keyFile+".pub")
		if err != nil {
			t.Fatalf("inspect failed: %v", err)
		}

		info := parseTokenInfo(t, inspectOut)
		assertValidation(t, info, true, "RS256")
		if info.Payload["sub"] != "rsa-user" {
			t.Errorf("expected sub rsa-user, got %v", info.Payload["sub"])
		}
	})

	t.Run("Bulk Payload", func(t *testing.T) {
		payloadFile := filepath.Join(tmpDir, "payload.json")
		payload := map[string]interface{}{
			"sub":   "bulk-user",
			"roles": []string{"admin"},
		}
		data, _ := json.Marshal(payload)
		if err := os.WriteFile(payloadFile, data, 0644); err != nil {
			t.Fatalf("failed to write payload file: %v", err)
		}

		out, _, err := execute("create", "--alg", "HS256", "--secret", "secret", "--payload", "@"+payloadFile)
		if err != nil {
			t.Fatalf("create failed: %v", err)
		}

		inspectOut, _, err := execute("inspect", out, "--secret", "secret")
		if err != nil {
			t.Fatalf("inspect failed: %v", err)
		}

		info := parseTokenInfo(t, inspectOut)
		assertValidation(t, info, true, "HS256")
		if info.Payload["sub"] != "bulk-user" {
			t.Errorf("expected sub bulk-user, got %v", info.Payload["sub"])
		}
	})
}
