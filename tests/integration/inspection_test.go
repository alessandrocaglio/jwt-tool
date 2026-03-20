package integration

import (
	"testing"
)

func TestTokenInspection(t *testing.T) {
	t.Run("Time Validation", func(t *testing.T) {
		tests := []struct {
			name           string
			createArgs     []string
			expectedStatus string
			expectedValid  bool
		}{
			{
				name:           "Expired Token",
				createArgs:     []string{"create", "--alg", "HS256", "--secret", "secret", "--exp", "-1h"},
				expectedStatus: "INVALID",
				expectedValid:  false,
			},
			{
				name:           "Token Valid in Future (NBF)",
				createArgs:     []string{"create", "--alg", "HS256", "--secret", "secret", "--nbf", "1h"},
				expectedStatus: "INVALID",
				expectedValid:  false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				token, _, err := execute(tt.createArgs...)
				if err != nil {
					t.Fatalf("failed to create token: %v", err)
				}

				out, _, _ := execute("inspect", token, "--secret", "secret")
				info := parseTokenInfo(t, out)

				if info.Validation.Status != tt.expectedStatus {
					t.Errorf("expected status %s, got %s", tt.expectedStatus, info.Validation.Status)
				}
				if info.Validation.Valid != tt.expectedValid {
					t.Errorf("expected valid %v, got %v", tt.expectedValid, info.Validation.Valid)
				}
			})
		}
	})

	t.Run("Leeway", func(t *testing.T) {
		// Create an expired token
		token, _, _ := execute("create", "--alg", "HS256", "--secret", "secret", "--exp", "-30s")

		// Inspect without leeway -> should be invalid
		out, _, _ := execute("inspect", token, "--secret", "secret")
		info := parseTokenInfo(t, out)
		if info.Validation.Valid {
			t.Error("expected token to be invalid without leeway")
		}

		// Inspect with 60s leeway -> should be valid
		out, _, _ = execute("inspect", token, "--secret", "secret", "--leeway", "60s")
		info = parseTokenInfo(t, out)
		if !info.Validation.Valid {
			t.Errorf("expected token to be valid with leeway, got error: %s", info.Validation.Error)
		}
	})
}
