package jwks

import (
	"fmt"

	"github.com/go-jose/go-jose/v3"
)

func GenerateJWKS(pubKeys []interface{}, kids []string) (*jose.JSONWebKeySet, error) {
	jwkSet := &jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, 0, len(pubKeys)),
	}

	for i, pubKey := range pubKeys {
		jwk := jose.JSONWebKey{
			Key: pubKey,
			Use: "sig",
		}

		if i < len(kids) {
			jwk.KeyID = kids[i]
		}

		if !jwk.IsPublic() {
			return nil, fmt.Errorf("key at position %d is not a public key", i)
		}

		jwkSet.Keys = append(jwkSet.Keys, jwk)
	}

	return jwkSet, nil
}
