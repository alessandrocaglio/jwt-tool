package verifier

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestDecode(t *testing.T) {
	t.Run("Valid JWT", func(t *testing.T) {
		header := map[string]interface{}{"alg": "HS256", "typ": "JWT"}
		payload := map[string]interface{}{"sub": "1234567890", "name": "John Doe"}

		tokenStr := createUnsignedToken(header, payload) + ".fake-signature"

		info, err := Decode(tokenStr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if info.Header["alg"] != "HS256" {
			t.Errorf("expected alg HS256, got %v", info.Header["alg"])
		}
		if info.Payload["sub"] != "1234567890" {
			t.Errorf("expected sub 1234567890, got %v", info.Payload["sub"])
		}
		if info.Signature != "fake-signature" {
			t.Errorf("expected signature fake-signature, got %s", info.Signature)
		}
	})

	t.Run("Malformed JWT (wrong parts)", func(t *testing.T) {
		_, err := Decode("not.a.jwt")
		if err == nil {
			t.Error("expected error for malformed token, got nil")
		}
	})

	t.Run("Invalid Base64", func(t *testing.T) {
		_, err := Decode("abc.def.ghi")
		if err == nil {
			t.Error("expected error for invalid base64 payload, got nil")
		}
	})

	t.Run("Valid Header but invalid Payload JSON", func(t *testing.T) {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{invalid-json}`))
		token := header + "." + payload + ".sig"

		_, err := Decode(token)
		if err == nil {
			t.Error("expected error for invalid payload JSON, got nil")
		}
	})
}

// Helper to create an unsigned JWT part (header.payload)
func createUnsignedToken(header, payload map[string]interface{}) string {
	hJSON, _ := json.Marshal(header)
	pJSON, _ := json.Marshal(payload)

	return base64.RawURLEncoding.EncodeToString(hJSON) + "." +
		base64.RawURLEncoding.EncodeToString(pJSON)
}
