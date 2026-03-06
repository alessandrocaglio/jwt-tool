package verifier

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"jwt-tool/pkg/models"
)

// Decode parses a JWT string without verifying the signature.
func Decode(tokenStr string) (*models.TokenInfo, error) {
	parser := jwt.NewParser()
	claims := jwt.MapClaims{}
	token, _, err := parser.ParseUnverified(tokenStr, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	parts := strings.Split(tokenStr, ".")
	signature := ""
	if len(parts) == 3 {
		signature = parts[2]
	}

	return &models.TokenInfo{
		Header:    token.Header,
		Payload:   claims,
		Signature: signature,
	}, nil
}
