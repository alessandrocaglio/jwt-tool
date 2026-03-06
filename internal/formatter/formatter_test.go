package formatter

import (
	"encoding/json"
	"testing"

	"jwt-tool/pkg/models"
)

func TestIsTimestampKey(t *testing.T) {
	tests := []struct {
		key      string
		expected bool
	}{
		{"exp", true},
		{"iat", true},
		{"nbf", true},
		{"auth_time", true},
		{"updated_at", true},
		{"sub", false},
		{"iss", false},
	}

	for _, tt := range tests {
		if got := isTimestampKey(tt.key); got != tt.expected {
			t.Errorf("isTimestampKey(%q) = %v, want %v", tt.key, got, tt.expected)
		}
	}
}

func TestConvertToFloat(t *testing.T) {
	tests := []struct {
		val      interface{}
		expected float64
		ok       bool
	}{
		{float64(123), 123, true},
		{int64(456), 456, true},
		{int(789), 789, true},
		{json.Number("101112"), 101112, true},
		{"not-a-number", 0, false},
	}

	for _, tt := range tests {
		got, ok := convertToFloat(tt.val)
		if ok != tt.ok {
			t.Errorf("convertToFloat(%v) ok = %v, want %v", tt.val, ok, tt.ok)
		}
		if ok && got != tt.expected {
			t.Errorf("convertToFloat(%v) got = %v, want %v", tt.val, got, tt.expected)
		}
	}
}

func TestPrintTokenSummary(t *testing.T) {
	// This test mainly ensures it doesn't panic
	info := &models.TokenInfo{
		Header: map[string]interface{}{
			"alg": "HS256",
		},
		Payload: map[string]interface{}{
			"sub": "1234567890",
			"iat": 1700000000,
		},
		Signature: "some-signature",
	}

	// Capture output or just run it
	PrintTokenSummary(info)
}
