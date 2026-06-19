package authenticators

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/oauth2"
)

func newDPoPJWT(
	t *testing.T,
	key *ecdsa.PrivateKey,
	rawToken string,
	method string,
	uri string,
) string {
	t.Helper()

	tokenHash := sha256.Sum256([]byte(rawToken))
	accessTokenHash := base64.RawURLEncoding.EncodeToString(tokenHash[:])

	options := (&jose.SignerOptions{}).
		WithType("dpop+jwt").
		WithHeader("jwk", jose.JSONWebKey{
			Key:       key.Public(),
			Algorithm: string(jose.ES256),
			Use:       "sig",
		})

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.ES256,
			Key:       key,
		},
		options,
	)
	require.NoError(t, err)

	proof, err := jwt.Signed(signer).
		Claims(oauth2.DPoPClaims{
			HTTPMethod:      method,
			HTTPURI:         uri,
			AccessTokenHash: accessTokenHash,
			IssuedAt:        oauth2.NumericDate(time.Now().Unix()),
			JTI:             "jti",
		}).
		Serialize()
	require.NoError(t, err)

	return proof
}
