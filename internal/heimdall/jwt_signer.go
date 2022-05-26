package heimdall

import "time"

type JWTSigner interface {
	Sign(sub string, ttl time.Duration, claims map[string]any) (string, error)
	Hash() string
}
