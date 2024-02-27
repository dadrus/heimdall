package authenticators

import "github.com/go-jose/go-jose/v4"

func supportedAlgorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{
		// ECDSA
		jose.ES256, jose.ES384, jose.ES512, jose.EdDSA,
		// RSA-PSS
		jose.PS256, jose.PS384, jose.PS512,
		// RSA PKCS1 v1.5
		jose.RS256, jose.RS384, jose.RS512,
		// HMAC
		jose.HS256, jose.HS384, jose.HS512,
	}
}
