package models

import "github.com/golang-jwt/jwt/v5"

// ValidationInfo holds the results of a cryptographic verification.
type ValidationInfo struct {
	Valid     bool   `json:"valid"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	Leeway    string `json:"leeway,omitempty"`
}

// TokenInfo holds the decoded parts of a JWT and optional validation metadata.
type TokenInfo struct {
	Header     map[string]interface{} `json:"header"`
	Payload    jwt.MapClaims          `json:"payload"`
	Signature  string                 `json:"signature"`
	Validation *ValidationInfo        `json:"x-validation,omitempty"`
}
