package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"

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

				assert.Equal(t, "foo", signer.Name())
				assert.Equal(t, rsaPrivKey1, signer.key)
				assert.Equal(t, "bar", signer.KeyID())
				assert.Equal(t, string(jose.PS256), signer.Algorithm())
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
