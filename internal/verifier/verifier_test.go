package verifier

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerify(t *testing.T) {
	secret := []byte("my-secret")

	t.Run("Valid HMAC token", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "1234567890",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		tokenStr, _ := token.SignedString(secret)

		opts := VerifyOptions{
			Secret:     secret,
			Algorithms: []string{"HS256"},
		}

		info, err := Verify(tokenStr, opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if info.Payload["sub"] != "1234567890" {
			t.Errorf("expected sub 1234567890, got %v", info.Payload["sub"])
		}
	})

	t.Run("Invalid HMAC secret", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "1234567890",
		})
		tokenStr, _ := token.SignedString([]byte("wrong-secret"))

		opts := VerifyOptions{
			Secret:     secret,
			Algorithms: []string{"HS256"},
		}

		_, err := Verify(tokenStr, opts)
		if err == nil {
			t.Error("expected error for invalid signature, got nil")
		}
	})

	t.Run("Expired token", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"exp": time.Now().Add(-time.Hour).Unix(),
		})
		tokenStr, _ := token.SignedString(secret)

		opts := VerifyOptions{
			Secret:     secret,
			Algorithms: []string{"HS256"},
		}

		_, err := Verify(tokenStr, opts)
		if err == nil {
			t.Error("expected error for expired token, got nil")
		}
	})

	t.Run("None algorithm rejected", func(t *testing.T) {
		// Create a token with "none" alg
		// header: {"alg":"none","typ":"JWT"} -> eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
		// payload: {"sub":"123"} -> eyJzdWIiOiIxMjMifQ
		tokenStr := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ."

		opts := VerifyOptions{
			Algorithms: []string{"HS256"},
		}

		_, err := Verify(tokenStr, opts)
		if err == nil {
			t.Error("expected error for 'none' algorithm, got nil")
		}
	})
}
