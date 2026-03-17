package integration

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestFullLifecycleAsymmetric(t *testing.T) {
	binaryPath := "../../jwt-tool-lifecycle-test"
	build := exec.Command("go", "build", "-o", binaryPath, "../../cmd/jwt-tool/main.go")
	if err := build.Run(); err != nil {
		t.Fatalf("failed to build jwt-tool: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(binaryPath)
		os.Remove("test_rsa")
		os.Remove("test_rsa.pub")
	})

	// 1. Keygen: Generate RSA key pair
	keygenCmd := exec.Command(binaryPath, "keygen", "-a", "rsa", "-f", "test_rsa")
	if err := keygenCmd.Run(); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	// 2. Create: Sign a token using the private key
	createCmd := exec.Command(binaryPath, "create", "--alg", "RS256", "--pem", "@test_rsa", "--sub", "asymmetric-user", "--exp", "1h")
	var tokenOut bytes.Buffer
	createCmd.Stdout = &tokenOut
	if err := createCmd.Run(); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	token := tokenOut.String()

	// 3. Inspect: Verify the token using the public key
	inspectCmd := exec.Command(binaryPath, "inspect", "-", "--pem", "@test_rsa.pub")
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

	validation := info["x-validation"].(map[string]interface{})
	if validation["valid"] != true {
		t.Errorf("asymmetric validation failed: %v", validation["error"])
	}
	if validation["algorithm"] != "RS256" {
		t.Errorf("expected RS256, got %v", validation["algorithm"])
	}
}

func TestTimeValidation(t *testing.T) {
	binaryPath := "../../jwt-tool-time-test"
	build := exec.Command("go", "build", "-o", binaryPath, "../../cmd/jwt-tool/main.go")
	if err := build.Run(); err != nil {
		t.Fatalf("failed to build jwt-tool: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(binaryPath)
	})

	secret := "time-secret"

	tests := []struct {
		name           string
		createArgs     []string
		expectedStatus string
		expectedValid  bool
		expectedExit   int
	}{
		{
			name:           "Expired Token",
			createArgs:     []string{"create", "--alg", "HS256", "--secret", secret, "--exp", "-1h"},
			expectedStatus: "INVALID",
			expectedValid:  false,
			expectedExit:   2,
		},
		{
			name:           "Token Valid in Future (NBF)",
			createArgs:     []string{"create", "--alg", "HS256", "--secret", secret, "--nbf", "1h"},
			expectedStatus: "INVALID",
			expectedValid:  false,
			expectedExit:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 1. Create the token
			createCmd := exec.Command(binaryPath, tt.createArgs...)
			var tokenOut bytes.Buffer
			createCmd.Stdout = &tokenOut
			if err := createCmd.Run(); err != nil {
				t.Fatalf("create failed: %v", err)
			}
			token := tokenOut.String()

			// 2. Inspect the token
			inspectCmd := exec.Command(binaryPath, "inspect", "-", "--secret", secret)
			inspectCmd.Stdin = bytes.NewBufferString(token)
			var inspectOut bytes.Buffer
			inspectCmd.Stdout = &inspectOut
			
			// We expect an error exit code for these cases
			err := inspectCmd.Run()
			if tt.expectedExit == 0 {
				if err != nil {
					t.Fatalf("inspect failed unexpectedly: %v", err)
				}
			} else {
				if exitError, ok := err.(*exec.ExitError); ok {
					if exitError.ExitCode() != tt.expectedExit {
						t.Errorf("expected exit code %d, got %d", tt.expectedExit, exitError.ExitCode())
					}
				} else if err == nil {
					t.Errorf("expected exit code %d, but command succeeded", tt.expectedExit)
				}
			}

			// 3. Verify JSON output status
			var info map[string]interface{}
			if err := json.Unmarshal(inspectOut.Bytes(), &info); err != nil {
				t.Fatalf("failed to parse inspect output: %v", err)
			}

			validation := info["x-validation"].(map[string]interface{})
			if validation["status"] != tt.expectedStatus {
				t.Errorf("expected status %s, got %s", tt.expectedStatus, validation["status"])
			}
			if validation["valid"] != tt.expectedValid {
				t.Errorf("expected valid %v, got %v", tt.expectedValid, validation["valid"])
			}
		})
	}
}

func TestSecurityKeyConfusion(t *testing.T) {
	binaryPath := "../../jwt-tool-security-test"
	build := exec.Command("go", "build", "-o", binaryPath, "../../cmd/jwt-tool/main.go")
	if err := build.Run(); err != nil {
		t.Fatalf("failed to build jwt-tool: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(binaryPath)
		os.Remove("test_ecdsa")
		os.Remove("test_ecdsa.pub")
	})

	// 1. Generate a valid ECDSA key pair
	keygenCmd := exec.Command(binaryPath, "keygen", "-a", "ecdsa", "-f", "test_ecdsa")
	if err := keygenCmd.Run(); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	// 2. Create a symmetric HS256 token
	secret := "my-secret"
	createCmd := exec.Command(binaryPath, "create", "--alg", "HS256", "--secret", secret, "--exp", "1h")
	var tokenOut bytes.Buffer
	createCmd.Stdout = &tokenOut
	if err := createCmd.Run(); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	token := tokenOut.String()

	// 3. Try to verify it using a Public Key PEM (this should fail validation)
	inspectCmd := exec.Command(binaryPath, "inspect", "-", "--pem", "@test_ecdsa.pub")
	inspectCmd.Stdin = bytes.NewBufferString(token)
	var inspectOut bytes.Buffer
	var inspectErr bytes.Buffer
	inspectCmd.Stdout = &inspectOut
	inspectCmd.Stderr = &inspectErr
	
	// Should fail with exit code 2 (validation failure)
	err := inspectCmd.Run()
	if err == nil {
		t.Fatal("expected inspection to fail for algorithm mismatch (HS256 vs --pem), but it succeeded")
	}

	if inspectOut.Len() == 0 {
		t.Fatalf("inspect output is empty. Stderr: %s", inspectErr.String())
	}

	var info map[string]interface{}
	if err := json.Unmarshal(inspectOut.Bytes(), &info); err != nil {
		t.Fatalf("failed to parse inspect output: %v. Output: %s", err, inspectOut.String())
	}

	validation := info["x-validation"].(map[string]interface{})
	if validation["valid"] == true {
		t.Fatal("security vulnerability: HS256 token validated using --pem flag")
	}
	
	expectedErrorPart := "missing secret for HMAC algorithm HS256"
	actualError := validation["error"].(string)
	if !strings.Contains(actualError, expectedErrorPart) {
		t.Errorf("expected error to contain %q, got %q", expectedErrorPart, actualError)
	}
}

func TestResolverPattern(t *testing.T) {
	binaryPath := "../../jwt-tool-resolver-test"
	build := exec.Command("go", "build", "-o", binaryPath, "../../cmd/jwt-tool/main.go")
	if err := build.Run(); err != nil {
		t.Fatalf("failed to build jwt-tool: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(binaryPath)
		os.Remove("secret.txt")
		os.Remove("token.jwt")
	})

	secret := "resolver-secret"
	os.WriteFile("secret.txt", []byte(secret), 0644)

	// 1. Create token and save to file
	createCmd := exec.Command(binaryPath, "create", "--alg", "HS256", "--secret", "@secret.txt", "--exp", "1h")
	var tokenOut bytes.Buffer
	createCmd.Stdout = &tokenOut
	if err := createCmd.Run(); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	token := tokenOut.String()
	os.WriteFile("token.jwt", []byte(token), 0644)

	// 2. Inspect using @file for both token and secret
	inspectCmd := exec.Command(binaryPath, "inspect", "@token.jwt", "--secret", "@secret.txt")
	var inspectOut bytes.Buffer
	inspectCmd.Stdout = &inspectOut
	if err := inspectCmd.Run(); err != nil {
		t.Fatalf("inspect failed: %v", err)
	}

	var info map[string]interface{}
	if err := json.Unmarshal(inspectOut.Bytes(), &info); err != nil {
		t.Fatalf("failed to parse inspect output: %v", err)
	}

	validation := info["x-validation"].(map[string]interface{})
	if validation["valid"] != true {
		t.Errorf("resolver pattern validation failed: %v", validation["error"])
	}
}

func TestBulkPayloadLoading(t *testing.T) {
	binaryPath := "../../jwt-tool-payload-test"
	build := exec.Command("go", "build", "-o", binaryPath, "../../cmd/jwt-tool/main.go")
	if err := build.Run(); err != nil {
		t.Fatalf("failed to build jwt-tool: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(binaryPath)
		os.Remove("payload.json")
	})

	payload := map[string]interface{}{
		"sub": "bulk-user",
		"roles": []string{"admin", "editor"},
		"nested": map[string]interface{}{
			"key": "value",
		},
	}
	payloadBytes, _ := json.Marshal(payload)
	os.WriteFile("payload.json", payloadBytes, 0644)

	// 1. Create token using --payload
	createCmd := exec.Command(binaryPath, "create", "--alg", "HS256", "--secret", "secret", "--payload", "@payload.json", "--exp", "1h")
	var tokenOut bytes.Buffer
	createCmd.Stdout = &tokenOut
	if err := createCmd.Run(); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	token := tokenOut.String()

	// 2. Inspect and verify payload structure
	inspectCmd := exec.Command(binaryPath, "inspect", "-", "--secret", "secret")
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

	decodedPayload := info["payload"].(map[string]interface{})
	if decodedPayload["sub"] != "bulk-user" {
		t.Errorf("expected sub bulk-user, got %v", decodedPayload["sub"])
	}
	roles := decodedPayload["roles"].([]interface{})
	if len(roles) != 2 || roles[0] != "admin" {
		t.Errorf("nested array roles not preserved correctly")
	}
	nested := decodedPayload["nested"].(map[string]interface{})
	if nested["key"] != "value" {
		t.Errorf("nested object not preserved correctly")
	}
}
