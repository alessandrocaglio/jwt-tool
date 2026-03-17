package integration

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

func TestCreateAndInspect(t *testing.T) {
	binaryPath := "../../jwt-tool-test"
	// Build the binary first
	build := exec.Command("go", "build", "-o", binaryPath, "../../cmd/jwt-tool/main.go")
	if err := build.Run(); err != nil {
		t.Fatalf("failed to build jwt-tool: %v", err)
	}

	// Clean up the binary after tests
	t.Cleanup(func() {
		os.Remove(binaryPath)
	})

	tests := []struct {
		name       string
		createArgs []string
		verifyArgs []string
		wantSub    string
	}{
		{
			name:       "HMAC Create and Verify",
			createArgs: []string{"create", "--alg", "HS256", "--secret", "test-secret", "--sub", "test-user", "--exp", "1h"},
			verifyArgs: []string{"inspect", "-", "--secret", "test-secret"},
			wantSub:    "test-user",
		},
		{
			name:       "HMAC Sign Alias and Verify",
			createArgs: []string{"sign", "--alg", "HS256", "--secret", "test-secret", "--sub", "test-user", "--exp", "1h"},
			verifyArgs: []string{"inspect", "-", "--secret", "test-secret"},
			wantSub:    "test-user",
		},
		{
			name:       "HMAC Create and Verify with Claims",
			createArgs: []string{"create", "--alg", "HS256", "--secret", "test-secret", "--claim", "role=admin", "--claim", "id=123", "--exp", "1h"},
			verifyArgs: []string{"inspect", "-", "--secret", "test-secret"},
			wantSub:    "", // no sub provided
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 1. Create
			createCmd := exec.Command(binaryPath, tt.createArgs...)
			var tokenOut bytes.Buffer
			createCmd.Stdout = &tokenOut
			if err := createCmd.Run(); err != nil {
				t.Fatalf("create failed: %v", err)
			}

			token := tokenOut.String()

			// 2. Inspect
			inspectCmd := exec.Command(binaryPath, tt.verifyArgs...)
			inspectCmd.Stdin = bytes.NewBufferString(token)
			var inspectOut bytes.Buffer
			inspectCmd.Stdout = &inspectOut
			if err := inspectCmd.Run(); err != nil {
				t.Fatalf("inspect failed: %v", err)
			}

			var info map[string]interface{}
			if err := json.Unmarshal(inspectOut.Bytes(), &info); err != nil {
				t.Fatalf("failed to parse inspect output: %v", err)
			}

			payload := info["payload"].(map[string]interface{})
			if tt.wantSub != "" && payload["sub"] != tt.wantSub {
				t.Errorf("got sub %v, want %v", payload["sub"], tt.wantSub)
			}

			validation := info["x-validation"].(map[string]interface{})
			if validation["valid"] != true {
				t.Errorf("token validation failed: %v", validation["error"])
			}
		})
	}
}
