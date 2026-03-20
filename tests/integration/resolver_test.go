package integration

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolver(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("Stdin", func(t *testing.T) {
		token, _, _ := execute("create", "--alg", "HS256", "--secret", "secret")

		// Inspect from stdin
		out, _, err := executeWithInput(token, "inspect", "-", "--secret", "secret")
		if err != nil {
			t.Fatalf("inspect from stdin failed: %v", err)
		}
		info := parseTokenInfo(t, out)
		assertValidation(t, info, true, "HS256")
	})

	t.Run("File (@path)", func(t *testing.T) {
		secretFile := filepath.Join(tmpDir, "secret.txt")
		if err := os.WriteFile(secretFile, []byte("secret"), 0644); err != nil {
			t.Fatalf("failed to write secret file: %v", err)
		}

		token, _, _ := execute("create", "--alg", "HS256", "--secret", "@"+secretFile)

		tokenFile := filepath.Join(tmpDir, "token.jwt")
		if err := os.WriteFile(tokenFile, []byte(token), 0644); err != nil {
			t.Fatalf("failed to write token file: %v", err)
		}

		// Inspect from file
		out, _, err := execute("inspect", "@"+tokenFile, "--secret", "@"+secretFile)
		if err != nil {
			t.Fatalf("inspect from file failed: %v", err)
		}
		info := parseTokenInfo(t, out)
		assertValidation(t, info, true, "HS256")
	})
}
