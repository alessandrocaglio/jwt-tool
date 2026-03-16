package keygen

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// KeyPair holds the PEM encoded private and public keys.
type KeyPair struct {
	PrivatePEM []byte
	PublicPEM  []byte
}

// GenerateEdDSA generates a new Ed25519 key pair.
func GenerateEdDSA() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not generate EdDSA key: %w", err)
	}

	// Encode Private Key (PKCS#8)
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("could not marshal private key: %w", err)
	}
	privBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}

	// Encode Public Key (PKIX)
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("could not marshal public key: %w", err)
	}
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}

	return &KeyPair{
		PrivatePEM: pem.EncodeToMemory(privBlock),
		PublicPEM:  pem.EncodeToMemory(pubBlock),
	}, nil
}

// GenerateRSA generates a new RSA key pair.
func GenerateRSA(bits int) (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("could not generate RSA key: %w", err)
	}

	// Encode Private Key (PKCS#8)
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("could not marshal private key: %w", err)
	}
	privBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}

	// Encode Public Key (PKIX)
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("could not marshal public key: %w", err)
	}
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}

	return &KeyPair{
		PrivatePEM: pem.EncodeToMemory(privBlock),
		PublicPEM:  pem.EncodeToMemory(pubBlock),
	}, nil
}

// GenerateECDSA generates a new ECDSA key pair using the specified curve.
func GenerateECDSA(curveName string) (*KeyPair, error) {
	var curve elliptic.Curve
	switch curveName {
	case "P256":
		curve = elliptic.P256()
	case "P384":
		curve = elliptic.P384()
	case "P521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curveName)
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not generate ECDSA key: %w", err)
	}

	// Encode Private Key (PKCS#8)
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("could not marshal private key: %w", err)
	}
	privBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}

	// Encode Public Key (PKIX)
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("could not marshal public key: %w", err)
	}
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}

	return &KeyPair{
		PrivatePEM: pem.EncodeToMemory(privBlock),
		PublicPEM:  pem.EncodeToMemory(pubBlock),
	}, nil
}
