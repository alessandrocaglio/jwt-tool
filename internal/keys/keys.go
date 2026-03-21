package keys

import (
	"crypto"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// ParsePublicKey parses a PEM-encoded public key into a crypto.PublicKey.
// It supports RSA, ECDSA, and EdDSA public keys.
func ParsePublicKey(pemData []byte) (crypto.PublicKey, error) {
	if pub, err := jwt.ParseRSAPublicKeyFromPEM(pemData); err == nil {
		return pub, nil
	} else if pub, err := jwt.ParseECPublicKeyFromPEM(pemData); err == nil {
		return pub, nil
	} else if pub, err := jwt.ParseEdPublicKeyFromPEM(pemData); err == nil {
		return pub, nil
	}
	return nil, fmt.Errorf("could not parse public key PEM (tried RSA, ECDSA, and EdDSA)")
}

// ParsePrivateKey parses a PEM-encoded private key into a crypto.PrivateKey.
// It supports RSA, ECDSA, and EdDSA private keys.
func ParsePrivateKey(pemData []byte) (crypto.PrivateKey, error) {
	if priv, err := jwt.ParseRSAPrivateKeyFromPEM(pemData); err == nil {
		return priv, nil
	} else if priv, err := jwt.ParseECPrivateKeyFromPEM(pemData); err == nil {
		return priv, nil
	} else if priv, err := jwt.ParseEdPrivateKeyFromPEM(pemData); err == nil {
		return priv, nil
	}
	return nil, fmt.Errorf("could not parse private key PEM (tried RSA, ECDSA, and EdDSA)")
}
