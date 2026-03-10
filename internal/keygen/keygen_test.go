package keygen

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestGenerateRSA(t *testing.T) {
	bits := 2048
	kp, err := GenerateRSA(bits)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Verify Private Key
	block, _ := pem.Decode(kp.PrivatePEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Errorf("invalid private key PEM")
	}
	_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("failed to parse PKCS8 private key: %v", err)
	}

	// Verify Public Key
	block, _ = pem.Decode(kp.PublicPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Errorf("invalid public key PEM")
	}
	_, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Errorf("failed to parse PKIX public key: %v", err)
	}
}

func TestGenerateECDSA(t *testing.T) {
	curves := []string{"P256", "P384", "P521"}
	for _, curve := range curves {
		t.Run(curve, func(t *testing.T) {
			kp, err := GenerateECDSA(curve)
			if err != nil {
				t.Fatalf("failed to generate ECDSA key for curve %s: %v", curve, err)
			}

			// Verify Private Key
			block, _ := pem.Decode(kp.PrivatePEM)
			if block == nil || block.Type != "PRIVATE KEY" {
				t.Errorf("invalid private key PEM")
			}
			_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				t.Errorf("failed to parse PKCS8 private key: %v", err)
			}

			// Verify Public Key
			block, _ = pem.Decode(kp.PublicPEM)
			if block == nil || block.Type != "PUBLIC KEY" {
				t.Errorf("invalid public key PEM")
			}
			_, err = x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				t.Errorf("failed to parse PKIX public key: %v", err)
			}
		})
	}
}

func TestGenerateECDSA_InvalidCurve(t *testing.T) {
	_, err := GenerateECDSA("invalid")
	if err == nil {
		t.Error("expected error for invalid curve, got nil")
	}
}
