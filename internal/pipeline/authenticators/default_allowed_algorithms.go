package authenticators

import "gopkg.in/square/go-jose.v2"

func defaultAllowedAlgorithms() []string {
	// RSA PKCS v1.5 is not allowed by intention
	return []string{
		// ECDSA
		string(jose.ES256), string(jose.ES384), string(jose.ES512),
		// RSA-PSS
		string(jose.PS256), string(jose.PS384), string(jose.PS512),
	}
}
