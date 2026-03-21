package signer

import (
	"crypto"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SignOptions defines the parameters for signing a JWT.
type SignOptions struct {
	Algorithm  string
	Secret     []byte
	PrivateKey crypto.PrivateKey
	Claims     jwt.MapClaims
	Header     map[string]interface{}
}

// ParseKeyValueSlice parses a slice of "key=value" strings into a map.
func ParseKeyValueSlice(input []string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	for _, c := range input {
		parts := strings.SplitN(c, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid format (expected key=value): %s", c)
		}
		// Try to parse as JSON if it looks like one, otherwise treat as string
		var val interface{}
		if err := json.Unmarshal([]byte(parts[1]), &val); err != nil {
			val = parts[1]
		}
		result[parts[0]] = val
	}
	return result, nil
}

// ValidateExpiration checks if the 'exp' claim is present and not too far in the future.
func (opts *SignOptions) ValidateExpiration() []string {
	var warnings []string
	now := time.Now()
	if exp, ok := opts.Claims["exp"].(*jwt.NumericDate); ok {
		if exp.Time.Sub(now) > 24*time.Hour {
			warnings = append(warnings, "expiration is more than 24 hours in the future")
		}
	} else if _, ok := opts.Claims["exp"]; !ok {
		warnings = append(warnings, "no expiration ('exp') claim provided. The token will never expire.")
	}
	return warnings
}

// Sign creates and signs a new JWT.
func Sign(opts SignOptions) (string, error) {
	// 1. Choose Method
	var method jwt.SigningMethod
	switch opts.Algorithm {
	case "HS256":
		method = jwt.SigningMethodHS256
	case "HS384":
		method = jwt.SigningMethodHS384
	case "HS512":
		method = jwt.SigningMethodHS512
	case "RS256":
		method = jwt.SigningMethodRS256
	case "RS384":
		method = jwt.SigningMethodRS384
	case "RS512":
		method = jwt.SigningMethodRS512
	case "PS256":
		method = jwt.SigningMethodPS256
	case "PS384":
		method = jwt.SigningMethodPS384
	case "PS512":
		method = jwt.SigningMethodPS512
	case "ES256":
		method = jwt.SigningMethodES256
	case "ES384":
		method = jwt.SigningMethodES384
	case "ES512":
		method = jwt.SigningMethodES512
	case "EdDSA":
		method = jwt.SigningMethodEdDSA
	case "none":
		return "", fmt.Errorf("algorithm 'none' is not allowed")
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", opts.Algorithm)
	}

	// 2. Create Token
	token := jwt.NewWithClaims(method, opts.Claims)

	// 3. Add extra header fields
	for k, v := range opts.Header {
		token.Header[k] = v
	}

	// 4. Determine Signing Key
	var key interface{}
	switch opts.Algorithm[:2] {
	case "HS":
		if opts.Secret == nil {
			return "", fmt.Errorf("missing secret for HMAC algorithm %s", opts.Algorithm)
		}
		key = opts.Secret
	case "RS", "PS", "ES", "Ed":
		if opts.PrivateKey == nil {
			return "", fmt.Errorf("missing private key for algorithm %s", opts.Algorithm)
		}
		key = opts.PrivateKey
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", opts.Algorithm)
	}

	// 5. Sign and Return
	return token.SignedString(key)
}
