package verifier

import (
	"crypto"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v5"
	"jwt-tool/pkg/models"
)

// VerifyOptions defines the parameters for signature and claims verification.
type VerifyOptions struct {
	Secret     []byte
	PublicKey  crypto.PublicKey
	JWKS       *jose.JSONWebKeySet
	Leeway     time.Duration
	Algorithms []string
}

// Verify validates the JWT signature and claims.
func Verify(tokenStr string, opts VerifyOptions) (*models.TokenInfo, error) {
	parser := jwt.NewParser(
		jwt.WithLeeway(opts.Leeway),
		jwt.WithValidMethods(opts.Algorithms),
	)

	claims := jwt.MapClaims{}
	token, err := parser.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		// Key Selection Logic
		switch token.Method.Alg() {
		case "HS256", "HS384", "HS512":
			if opts.Secret == nil {
				return nil, fmt.Errorf("missing secret for HMAC algorithm %s", token.Method.Alg())
			}
			return opts.Secret, nil
		case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512":
			if opts.PublicKey != nil {
				return opts.PublicKey, nil
			}

			if opts.JWKS != nil {
				kid, _ := token.Header["kid"].(string)
				if kid == "" {
					// Fallback: If no kid, try all keys in the set (or first one)
					// But security-wise, kid is usually required for JWKS.
					// Let's try to match by kid if present.
					if len(opts.JWKS.Keys) == 1 {
						return opts.JWKS.Keys[0].Key, nil
					}
					return nil, fmt.Errorf("missing kid in token header for JWKS verification")
				}
				keys := opts.JWKS.Key(kid)
				if len(keys) == 0 {
					return nil, fmt.Errorf("key with kid %s not found in JWKS", kid)
				}
				return keys[0].Key, nil
			}

			return nil, fmt.Errorf("missing public key or JWKS for algorithm %s", token.Method.Alg())
		case "none":
			return nil, fmt.Errorf("algorithm 'none' is not allowed")
		default:
			return nil, fmt.Errorf("unsupported algorithm: %s", token.Method.Alg())
		}
	})

	if err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	// Re-use Decode logic to return the models.TokenInfo
	info, _ := Decode(tokenStr)
	return info, nil
}
