package integration

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKeygen(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name string
		args []string
		priv string
		pub  string
	}{
		{
			name: "RSA default",
			args: []string{"keygen", "-a", "rsa", "-f", filepath.Join(tmpDir, "rsa")},
			priv: filepath.Join(tmpDir, "rsa"),
			pub:  filepath.Join(tmpDir, "rsa.pub"),
		},
		{
			name: "ECDSA P256",
			args: []string{"keygen", "-a", "ecdsa", "-c", "P256", "-f", filepath.Join(tmpDir, "ecdsa")},
			priv: filepath.Join(tmpDir, "ecdsa"),
			pub:  filepath.Join(tmpDir, "ecdsa.pub"),
		},
		{
			name: "EdDSA",
			args: []string{"keygen", "-a", "eddsa", "-f", filepath.Join(tmpDir, "eddsa")},
			priv: filepath.Join(tmpDir, "eddsa"),
			pub:  filepath.Join(tmpDir, "eddsa.pub"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := execute(tt.args...)
			if err != nil {
				t.Fatalf("keygen failed: %v", err)
			}

			if _, err := os.Stat(tt.priv); os.IsNotExist(err) {
				t.Errorf("private key file %s not created", tt.priv)
			}
			if _, err := os.Stat(tt.pub); os.IsNotExist(err) {
				t.Errorf("public key file %s not created", tt.pub)
			}
		})
	}
}
