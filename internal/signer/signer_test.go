package signer

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestSign(t *testing.T) {
	// Generate keys for testing
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecdsaPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name     string
		opts     SignOptions
		wantErr  bool
		checkAlg string
	}{
		{
			name: "HS256 Success",
			opts: SignOptions{
				Algorithm: "HS256",
				Secret:    []byte("my-secret"),
				Claims:    jwt.MapClaims{"sub": "user123"},
			},
			wantErr:  false,
			checkAlg: "HS256",
		},
		{
			name: "RS256 Success",
			opts: SignOptions{
				Algorithm:  "RS256",
				PrivateKey: rsaPriv,
				Claims:     jwt.MapClaims{"sub": "user123"},
			},
			wantErr:  false,
			checkAlg: "RS256",
		},
		{
			name: "ES256 Success",
			opts: SignOptions{
				Algorithm:  "ES256",
				PrivateKey: ecdsaPriv,
				Claims:     jwt.MapClaims{"sub": "user123"},
			},
			wantErr:  false,
			checkAlg: "ES256",
		},
		{
			name: "EdDSA Success",
			opts: SignOptions{
				Algorithm:  "EdDSA",
				PrivateKey: edPriv,
				Claims:     jwt.MapClaims{"sub": "user123"},
			},
			wantErr:  false,
			checkAlg: "EdDSA",
		},
		{
			name: "Algorithm None Rejected",
			opts: SignOptions{
				Algorithm: "none",
				Claims:    jwt.MapClaims{"sub": "user123"},
			},
			wantErr: true,
		},
		{
			name: "Missing Secret for HMAC",
			opts: SignOptions{
				Algorithm: "HS256",
				Claims:    jwt.MapClaims{"sub": "user123"},
			},
			wantErr: true,
		},
		{
			name: "Missing Private Key for RSA",
			opts: SignOptions{
				Algorithm: "RS256",
				Claims:    jwt.MapClaims{"sub": "user123"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Sign(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got == "" {
					t.Error("Sign() returned empty token string")
				}
				// Verify it's at least a valid looking JWT (3 parts)
				token, _ := jwt.Parse(got, func(token *jwt.Token) (interface{}, error) {
					return nil, nil // we don't care about validation here, just structure
				})
				if token == nil {
					t.Error("Sign() returned invalid JWT structure")
				} else if token.Method.Alg() != tt.checkAlg {
					t.Errorf("Sign() alg = %v, want %v", token.Method.Alg(), tt.checkAlg)
				}
			}
		})
	}
}
