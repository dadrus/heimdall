package heimdall

import (
	"time"

	"gopkg.in/square/go-jose.v2"
)

type JWTSigner interface {
	Sign(sub string, ttl time.Duration, claims map[string]any) (string, error)
	Hash() []byte
	Keys() []jose.JSONWebKey
}
