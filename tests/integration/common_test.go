package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"jawt/pkg/models"
)

var binaryPath string

func TestMain(m *testing.M) {
	// Build the binary once for all tests
	tmpDir, err := os.MkdirTemp("", "jawt-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	binaryPath = filepath.Join(tmpDir, "jawt")
	// Adjust path to main.go based on where tests are run (likely tests/integration)
	build := exec.Command("go", "build", "-o", binaryPath, "../../cmd/jawt/main.go")
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build jawt: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// execute runs the command and returns stdout, stderr and error
func execute(args ...string) (string, string, error) {
	return executeWithInput("", args...)
}

// executeWithInput runs the command with stdin and returns stdout, stderr and error
func executeWithInput(input string, args ...string) (string, string, error) {
	cmd := exec.Command(binaryPath, args...)
	if input != "" {
		cmd.Stdin = bytes.NewBufferString(input)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// parseTokenInfo unmarshals the JSON output into TokenInfo model
func parseTokenInfo(t *testing.T, output string) *models.TokenInfo {
	t.Helper()
	var info models.TokenInfo
	if err := json.Unmarshal([]byte(output), &info); err != nil {
		t.Fatalf("failed to parse JSON output: %v\nOutput: %s", err, output)
	}
	return &info
}

// assertValidation checks if the token is valid and matches the expected algorithm
func assertValidation(t *testing.T, info *models.TokenInfo, valid bool, alg string) {
	t.Helper()
	if info.Validation == nil {
		t.Fatalf("x-validation missing in output")
	}
	if info.Validation.Valid != valid {
		t.Errorf("expected valid=%v, got %v (Error: %s)", valid, info.Validation.Valid, info.Validation.Error)
	}
	if alg != "" && info.Validation.Algorithm != alg {
		t.Errorf("expected algorithm %s, got %v", alg, info.Validation.Algorithm)
	}
}
