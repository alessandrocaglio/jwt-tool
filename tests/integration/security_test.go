package integration

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurity(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("Key Confusion", func(t *testing.T) {
		// 1. Generate an RSA key
		keyFile := filepath.Join(tmpDir, "rsa_security")
		if _, _, err := execute("keygen", "-a", "rsa", "-f", keyFile); err != nil {
			t.Fatalf("keygen failed: %v", err)
		}

		// 2. Create a symmetric HS256 token
		token, _, err := execute("create", "--alg", "HS256", "--secret", "secret")
		if err != nil {
			t.Fatalf("create failed: %v", err)
		}

		// 3. Try to verify it using a Public Key PEM (should fail)
		out, _, _ := execute("inspect", token, "--pem", "@"+keyFile+".pub")
		info := parseTokenInfo(t, out)

		if info.Validation.Valid {
			t.Fatal("security vulnerability: HMAC token validated using --pem flag")
		}

		expectedError := "missing secret for HMAC algorithm HS256"
		if !strings.Contains(info.Validation.Error, expectedError) {
			t.Errorf("expected error %q, got %q", expectedError, info.Validation.Error)
		}
	})

	t.Run("Algorithm None", func(t *testing.T) {
		// Attempting to create alg=none should be rejected by the tool if possible,
		// or at least verification should fail.
		// Actually, our tool rejects it in runCreate and runInspect.

		// 1. Create with alg=none (should fail)
		_, stderr, err := execute("create", "--alg", "none", "--secret", "secret")
		if err == nil {
			t.Error("expected error when creating with alg=none")
		}
		if !strings.Contains(stderr, "unsupported algorithm") && !strings.Contains(stderr, "none") {
			t.Errorf("expected error message about unsupported algorithm, got: %s", stderr)
		}
	})
}
