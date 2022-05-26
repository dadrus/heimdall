package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/keystore/mocks"
	"github.com/dadrus/heimdall/internal/testsupport"
)

// nolint: maintidx
func TestNewJWTSigner(t *testing.T) {
	t.Parallel()

	const bitsInByte = 8

	rsaPrivKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rsaPrivKey2, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)

	rsaPrivKey3, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	ecdsaPrivKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecdsaPrivKey2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	ecdsaPrivKey3, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc             string
		config         config.Configuration
		configureMocks func(t *testing.T, mkf *mocks.MockKeyStore)
		assert         func(t *testing.T, err error, signer *jwtSigner)
	}{
		{
			uc: "no key id configured",
			config: config.Configuration{Signer: config.SignerConfig{
				Name: "foo",
			}},
			configureMocks: func(t *testing.T, mkf *mocks.MockKeyStore) {
				t.Helper()

				mkf.On("Entries").Return([]*keystore.Entry{
					{
						KeyID:      "bar",
						PrivateKey: rsaPrivKey1,
						Alg:        keystore.AlgRSA,
						KeySize:    rsaPrivKey1.Size() * bitsInByte,
					},
				})
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, rsaPrivKey1, signer.key)
				assert.Equal(t, "bar", signer.kid)
				assert.Equal(t, jose.PS256, signer.alg)
			},
		},
		{
			uc: "with key id configured",
			config: config.Configuration{Signer: config.SignerConfig{
				Name:  "foo",
				KeyID: "baz",
			}},
			configureMocks: func(t *testing.T, mkf *mocks.MockKeyStore) {
				t.Helper()

				mkf.On("GetKey", "baz").Return(&keystore.Entry{
					KeyID:      "baz",
					PrivateKey: rsaPrivKey2,
					Alg:        keystore.AlgRSA,
					KeySize:    rsaPrivKey2.Size() * bitsInByte,
				}, nil)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, rsaPrivKey2, signer.key)
				assert.Equal(t, "baz", signer.kid)
				assert.Equal(t, jose.PS384, signer.alg)
			},
		},
		{
			uc: "with error while retrieving key from key store",
			config: config.Configuration{Signer: config.SignerConfig{
				Name:  "foo",
				KeyID: "baz",
			}},
			configureMocks: func(t *testing.T, mkf *mocks.MockKeyStore) {
				t.Helper()

				mkf.On("GetKey", "baz").Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, testsupport.ErrTestPurpose, err)
			},
		},
		{
			uc: "with unsupported signature algorithm type",
			config: config.Configuration{Signer: config.SignerConfig{
				Name:  "foo",
				KeyID: "baz",
			}},
			configureMocks: func(t *testing.T, mkf *mocks.MockKeyStore) {
				t.Helper()

				mkf.On("GetKey", "baz").Return(&keystore.Entry{
					KeyID:      "baz",
					PrivateKey: rsaPrivKey2,
					Alg:        "FooBar",
					KeySize:    rsaPrivKey2.Size() * bitsInByte,
				}, nil)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "unsupported signature key")
			},
		},
		{
			uc:     "with rsa 2048 key",
			config: config.Configuration{Signer: config.SignerConfig{Name: "foo", KeyID: "baz"}},
			configureMocks: func(t *testing.T, mkf *mocks.MockKeyStore) {
				t.Helper()

				mkf.On("GetKey", "baz").Return(&keystore.Entry{
					KeyID:      "baz",
					PrivateKey: rsaPrivKey1,
					Alg:        keystore.AlgRSA,
					KeySize:    rsaPrivKey1.Size() * bitsInByte,
				}, nil)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, rsaPrivKey1, signer.key)
				assert.Equal(t, "baz", signer.kid)
				assert.Equal(t, jose.PS256, signer.alg)
			},
		},
		{
			uc:     "with rsa 3072 key",
			config: config.Configuration{Signer: config.SignerConfig{Name: "foo", KeyID: "baz"}},
			configureMocks: func(t *testing.T, mkf *mocks.MockKeyStore) {
				t.Helper()

				mkf.On("GetKey", "baz").Return(&keystore.Entry{
					KeyID:      "baz",
					PrivateKey: rsaPrivKey2,
					Alg:        keystore.AlgRSA,
					KeySize:    rsaPrivKey2.Size() * bitsInByte,
				}, nil)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, rsaPrivKey2, signer.key)
				assert.Equal(t, "baz", signer.kid)
				assert.Equal(t, jose.PS384, signer.alg)
			},
		},
		{
			uc:     "with rsa 4096 key",
			config: config.Configuration{Signer: config.SignerConfig{Name: "foo", KeyID: "baz"}},
			configureMocks: func(t *testing.T, mkf *mocks.MockKeyStore) {
				t.Helper()

				mkf.On("GetKey", "baz").Return(&keystore.Entry{
					KeyID:      "baz",
					PrivateKey: rsaPrivKey3,
					Alg:        keystore.AlgRSA,
					KeySize:    rsaPrivKey3.Size() * bitsInByte,
				}, nil)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, rsaPrivKey3, signer.key)
				assert.Equal(t, "baz", signer.kid)
				assert.Equal(t, jose.PS512, signer.alg)
			},
		},
		{
			uc:     "with P256 ecdsa key",
			config: config.Configuration{Signer: config.SignerConfig{Name: "foo", KeyID: "baz"}},
			configureMocks: func(t *testing.T, mkf *mocks.MockKeyStore) {
				t.Helper()

				mkf.On("GetKey", "baz").Return(&keystore.Entry{
					KeyID:      "baz",
					PrivateKey: ecdsaPrivKey1,
					Alg:        keystore.AlgECDSA,
					KeySize:    ecdsaPrivKey1.Params().BitSize,
				}, nil)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, ecdsaPrivKey1, signer.key)
				assert.Equal(t, "baz", signer.kid)
				assert.Equal(t, jose.ES256, signer.alg)
			},
		},
		{
			uc:     "with P384 ecdsa key",
			config: config.Configuration{Signer: config.SignerConfig{Name: "foo", KeyID: "baz"}},
			configureMocks: func(t *testing.T, mkf *mocks.MockKeyStore) {
				t.Helper()

				mkf.On("GetKey", "baz").Return(&keystore.Entry{
					KeyID:      "baz",
					PrivateKey: ecdsaPrivKey2,
					Alg:        keystore.AlgECDSA,
					KeySize:    ecdsaPrivKey2.Params().BitSize,
				}, nil)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, ecdsaPrivKey2, signer.key)
				assert.Equal(t, "baz", signer.kid)
				assert.Equal(t, jose.ES384, signer.alg)
			},
		},
		{
			uc:     "with P512 ecdsa key",
			config: config.Configuration{Signer: config.SignerConfig{Name: "foo", KeyID: "baz"}},
			configureMocks: func(t *testing.T, mkf *mocks.MockKeyStore) {
				t.Helper()

				mkf.On("GetKey", "baz").Return(&keystore.Entry{
					KeyID:      "baz",
					PrivateKey: ecdsaPrivKey3,
					Alg:        keystore.AlgECDSA,
					KeySize:    ecdsaPrivKey2.Params().BitSize,
				}, nil)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, ecdsaPrivKey3, signer.key)
				assert.Equal(t, "baz", signer.kid)
				assert.Equal(t, jose.ES384, signer.alg)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			ks := &mocks.MockKeyStore{}
			tc.configureMocks(t, ks)

			// WHEN
			signer, err := newJWTSigner(ks, tc.config, log.Logger)

			// THEN
			var (
				impl *jwtSigner
				ok   bool
			)

			if err == nil {
				impl, ok = signer.(*jwtSigner)
				require.True(t, ok)
			}

			tc.assert(t, err, impl)
		})
	}
}

func TestJWTSignerSign(t *testing.T) {
	t.Parallel()

	rsaPrivKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecdsaPrivKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	subjectID := "foobar"
	ttl := 10 * time.Minute

	for _, tc := range []struct {
		uc     string
		signer *jwtSigner
		claims map[string]any
		assert func(t *testing.T, err error, rawJWT string, signer *jwtSigner, claims map[string]any)
	}{
		{
			uc:     "sign with rsa",
			signer: &jwtSigner{iss: "foo", key: rsaPrivKey1, kid: "bar", alg: jose.RS256},
			claims: map[string]any{"baz": "zab", "bla": "foo"},
			assert: func(t *testing.T, err error, rawJWT string, signer *jwtSigner, claims map[string]any) {
				t.Helper()

				require.NoError(t, err)
				validateTestJWT(t, rawJWT, signer, subjectID, ttl, claims)
			},
		},
		{
			uc:     "sign with ecds",
			signer: &jwtSigner{iss: "foo", key: ecdsaPrivKey1, kid: "bar", alg: jose.ES256},
			claims: map[string]any{"baz": "zab", "bla": "foo"},
			assert: func(t *testing.T, err error, rawJWT string, signer *jwtSigner, claims map[string]any) {
				t.Helper()

				require.NoError(t, err)
				validateTestJWT(t, rawJWT, signer, subjectID, ttl, claims)
			},
		},
		{
			uc:     "sign with unsupported algorithm",
			signer: &jwtSigner{iss: "foo", key: rsaPrivKey1, kid: "bar", alg: jose.SignatureAlgorithm("foobar")},
			claims: map[string]any{"baz": "zab", "bla": "foo"},
			assert: func(t *testing.T, err error, rawJWT string, signer *jwtSigner, claims map[string]any) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "JWT signer")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			jwt, err := tc.signer.Sign(subjectID, ttl, tc.claims)

			// THEN
			tc.assert(t, err, jwt, tc.signer, tc.claims)
		})
	}
}

func validateTestJWT(t *testing.T, rawJWT string, signer *jwtSigner,
	subjectID string, ttl time.Duration, customClaims map[string]any,
) {
	t.Helper()

	const jwtDotCount = 2

	require.Equal(t, strings.Count(rawJWT, "."), jwtDotCount)

	token, err := jwt.ParseSigned(rawJWT)
	require.NoError(t, err)

	var jwtClaims map[string]any
	err = token.Claims(signer.key.Public(), &jwtClaims)
	require.NoError(t, err)

	assert.Contains(t, jwtClaims, "exp")
	assert.Contains(t, jwtClaims, "jti")
	assert.Contains(t, jwtClaims, "iat")
	assert.Contains(t, jwtClaims, "iss")
	assert.Contains(t, jwtClaims, "nbf")
	assert.Contains(t, jwtClaims, "sub")

	assert.Equal(t, subjectID, jwtClaims["sub"])
	assert.Equal(t, signer.iss, jwtClaims["iss"])

	exp, ok := jwtClaims["exp"].(float64)
	require.True(t, ok)
	nbf, ok := jwtClaims["nbf"].(float64)
	require.True(t, ok)
	iat, ok := jwtClaims["iat"].(float64)
	require.True(t, ok)

	now := time.Now().Unix()
	assert.True(t, float64(now) >= iat)

	assert.Equal(t, iat, nbf)
	assert.Equal(t, exp-ttl.Seconds(), nbf)

	for k, v := range customClaims {
		assert.Contains(t, jwtClaims, k)
		assert.Equal(t, v, jwtClaims[k])
	}
}
