package signer

import (
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

func TestNewJWTSigner(t *testing.T) {
	t.Parallel()

	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privateKey2, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc             string
		config         config.Configuration
		configureMocks func(t *testing.T, mkf *mocks.MockKeyStore)
		assert         func(t *testing.T, err error, signer *jwtSigner)
	}{
		{
			uc: "no signer id configured",
			config: config.Configuration{Signer: config.SignerConfig{
				Name: "foo",
			}},
			configureMocks: func(t *testing.T, mkf *mocks.MockKeyStore) {
				t.Helper()

				const bitsInByte = 8

				mkf.On("Entries").Return([]*keystore.Entry{
					{
						KeyID:      "bar",
						PrivateKey: privateKey1,
						Alg:        keystore.AlgRSA,
						KeySize:    privateKey1.Size() * bitsInByte,
					},
				})
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, privateKey1, signer.key)
				assert.Equal(t, "bar", signer.kid)
				assert.Equal(t, jose.PS256, signer.alg)
			},
		},
		{
			uc: "with id configured",
			config: config.Configuration{Signer: config.SignerConfig{
				Name:  "foo",
				KeyID: "baz",
			}},
			configureMocks: func(t *testing.T, mkf *mocks.MockKeyStore) {
				t.Helper()

				const bitsInByte = 8

				mkf.On("GetKey", "baz").Return(&keystore.Entry{
					KeyID:      "baz",
					PrivateKey: privateKey2,
					Alg:        keystore.AlgRSA,
					KeySize:    privateKey2.Size() * bitsInByte,
				}, nil)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, privateKey2, signer.key)
				assert.Equal(t, "baz", signer.kid)
				assert.Equal(t, jose.PS512, signer.alg)
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

				const bitsInByte = 8

				mkf.On("GetKey", "baz").Return(&keystore.Entry{
					KeyID:      "baz",
					PrivateKey: privateKey2,
					Alg:        "FooBar",
					KeySize:    privateKey2.Size() * bitsInByte,
				}, nil)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "unsupported signature key")
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
