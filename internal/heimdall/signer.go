package heimdall

import (
	"crypto"

	"gopkg.in/square/go-jose.v2"
)

type JWTSigner interface {
	Name() string
	KeyID() string
	Algorithm() jose.SignatureAlgorithm
	Key() crypto.Signer
}
