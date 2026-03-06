package models

import "github.com/golang-jwt/jwt/v5"

// TokenInfo holds the decoded parts of a JWT.
type TokenInfo struct {
	Header    map[string]interface{} `json:"header"`
	Payload   jwt.MapClaims          `json:"payload"`
	Signature string                 `json:"signature"`
}
