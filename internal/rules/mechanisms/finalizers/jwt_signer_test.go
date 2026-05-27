// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package finalizers

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	x509pkix "crypto/x509/pkix"
	"io"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/keyregistry"
	keyregistrymocks "github.com/dadrus/heimdall/internal/keyregistry/mocks"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

type unsupportedSigner struct{}

func (s unsupportedSigner) Public() crypto.PublicKey {
	return nil
}

func (s unsupportedSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, assert.AnError
}

func TestCreateJOSESigner(t *testing.T) {
	t.Parallel()

	rootCA, err := testsupport.NewRootCA("PEM Test Root CA", 24*time.Hour)
	require.NoError(t, err)

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	intermediateCert, err := rootCA.IssueCertificate(
		testsupport.WithSubject(x509pkix.Name{
			CommonName:   "PEM Test Intermediate CA",
			Organization: []string{"Heimdall"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour),
		testsupport.WithSubjectPubKey(&intermediateKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithIsCA(),
		testsupport.WithGeneratedSubjectKeyID(),
	)
	require.NoError(t, err)

	intermediateCA := testsupport.NewCA(intermediateKey, intermediateCert)

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	leafCert, err := intermediateCA.IssueCertificate(
		testsupport.WithSubject(x509pkix.Name{
			CommonName:   "PEM Test EE",
			Organization: []string{"Heimdall"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour),
		testsupport.WithSubjectPubKey(&privateKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
		testsupport.WithGeneratedSubjectKeyID(),
	)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		secret secrets.Secret
		assert func(t *testing.T, err error, signer jose.Signer)
	}{
		"secret not suitable for signing": {
			secret: secrettypes.NewStringSecret("bar", "baz"),
			assert: func(t *testing.T, err error, _ jose.Signer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "not suitable for signing")
			},
		},
		"certificate validation error": {
			secret: secrettypes.NewAsymmetricKeySecret("kid1", "kid1",
				privateKey, []*x509.Certificate{leafCert, rootCA.Certificate}),
			assert: func(t *testing.T, err error, _ jose.Signer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "unknown authority")
			},
		},
		"unsupported algorithm": {
			secret: secrettypes.NewAsymmetricKeySecret("unsupported", "unsupported",
				unsupportedSigner{}, nil),
			assert: func(t *testing.T, err error, _ jose.Signer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "unsupported key algorithm")
			},
		},
		"successful configuration": {
			secret: secrettypes.NewAsymmetricKeySecret("kid1", "kid1",
				privateKey, []*x509.Certificate{leafCert, intermediateCert, rootCA.Certificate}),
			assert: func(t *testing.T, err error, sig jose.Signer) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, sig)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			signer, err := createJOSESigner(tc.secret)

			tc.assert(t, err, signer)
		})
	}
}

func TestNewJWTSigner(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config *SignerConfig
		setup  func(t *testing.T, resolver *secretsmocks.ResolverMock)
		assert func(t *testing.T, err error, signer *jwtSigner)
	}{
		"creating informer fails": {
			config: &SignerConfig{Secret: config.Secret{Source: "foo", Selector: "bar"}},
			setup: func(t *testing.T, resolver *secretsmocks.ResolverMock) {
				t.Helper()

				resolver.EXPECT().
					Secret(mock.Anything, secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, _ *jwtSigner) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed creating secret informer")
			},
		},
		"successful configuration with default issuer": {
			config: &SignerConfig{
				Secret: config.Secret{Source: "signer", Selector: "jwt/signing/2026-05"},
			},
			setup: func(t *testing.T, resolver *secretsmocks.ResolverMock) {
				t.Helper()

				shm := secretsmocks.NewSecretHandleMock(t)
				shm.EXPECT().OnUpdate(mock.Anything)

				resolver.EXPECT().
					Secret(mock.Anything, secrets.Reference{
						Source:   "signer",
						Selector: "jwt/signing/2026-05",
					}).
					Return(shm, nil)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, signer)
				assert.Equal(t, "heimdall", signer.iss)
			},
		},
		"successful configuration with configured issuer": {
			config: &SignerConfig{
				Name:   "foo",
				Secret: config.Secret{Source: "signer", Selector: "jwt/signing/2026-05"},
			},
			setup: func(t *testing.T, resolver *secretsmocks.ResolverMock) {
				t.Helper()

				shm := secretsmocks.NewSecretHandleMock(t)
				shm.EXPECT().OnUpdate(mock.Anything)

				resolver.EXPECT().
					Secret(mock.Anything, secrets.Reference{
						Source:   "signer",
						Selector: "jwt/signing/2026-05",
					}).
					Return(shm, nil)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, signer)
				assert.Equal(t, "foo", signer.iss)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			resolver := secretsmocks.NewResolverMock(t)
			tc.setup(t, resolver)

			ko := keyregistrymocks.NewKeyObserverMock(t)
			ko.EXPECT().Notify(mock.MatchedBy(func(info any) bool { return info != nil })).Maybe()

			signer, err := newJWTSigner(t.Context(), tc.config, resolver, ko)
			tc.assert(t, err, signer)
		})
	}
}

func TestJWTSignerSign(t *testing.T) {
	t.Parallel()

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	secret := secrettypes.NewAsymmetricKeySecret("bar", "baz", privKey, nil)

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, hm *secretsmocks.SecretHandleMock)
		assert func(t *testing.T, err error, rawToken string)
	}{
		"signing material not available": {
			setup: func(t *testing.T, shm *secretsmocks.SecretHandleMock) {
				t.Helper()

				shm.EXPECT().OnUpdate(mock.Anything)
			},
			assert: func(t *testing.T, err error, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "jwt signing material is not available")
			},
		},
		"signing material available": {
			setup: func(t *testing.T, shm *secretsmocks.SecretHandleMock) {
				t.Helper()

				shm.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(t.Context(), secret)
						require.NoError(t, err)

						return true
					}))
			},
			assert: func(t *testing.T, err error, rawToken string) {
				t.Helper()

				require.NoError(t, err)

				parsed, err := jwt.ParseSigned(rawToken, []jose.SignatureAlgorithm{jose.ES384})
				require.NoError(t, err)

				assert.Len(t, parsed.Headers, 1)
				assert.Equal(t, "baz", parsed.Headers[0].KeyID)
				assert.Equal(t, "ES384", parsed.Headers[0].Algorithm)

				var claims map[string]any
				require.NoError(t, parsed.Claims(privKey.Public(), &claims))

				assert.Equal(t, "alice", claims["sub"])
				assert.Equal(t, "foo", claims["iss"])
				assert.Equal(t, "test", claims["scope"])
				assert.NotEmpty(t, claims["jti"])
				assert.NotEmpty(t, claims["iat"])
				assert.NotEmpty(t, claims["nbf"])
				assert.NotEmpty(t, claims["exp"])
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			shm := secretsmocks.NewSecretHandleMock(t)

			tc.setup(t, shm)

			resolver := secretsmocks.NewResolverMock(t)
			resolver.EXPECT().
				Secret(mock.Anything, secrets.Reference{
					Source:   "signer",
					Selector: "jwt/signing/2026-05",
				}).
				Return(shm, nil)

			ko := keyregistrymocks.NewKeyObserverMock(t)
			ko.EXPECT().
				Notify(mock.MatchedBy(func(ki keyregistry.KeyInfo) bool {
					return ki.Key == secret && ki.Exportable
				})).
				Maybe()

			signer, err := newJWTSigner(
				t.Context(),
				&SignerConfig{
					Name:   "foo",
					Secret: config.Secret{Source: "signer", Selector: "jwt/signing/2026-05"},
				},
				resolver,
				ko,
			)
			require.NoError(t, err)

			rawToken, err := signer.Sign("alice", time.Minute, map[string]any{"scope": "test"})

			tc.assert(t, err, rawToken)
		})
	}
}

func TestJWTSignerOnSecretUpdated(t *testing.T) {
	t.Parallel()

	// GIVEN
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	secret := secrettypes.NewAsymmetricKeySecret("bar", "baz", privKey, nil)

	kr := keyregistrymocks.NewRegistryMock(t)
	kr.EXPECT().Notify(mock.MatchedBy(func(info keyregistry.KeyInfo) bool {
		return info.Key == secret && info.Exportable
	}))

	signer := jwtSigner{ko: kr}

	// WHEN
	signer.onSecretUpdated(t.Context(), secret, nil)

	// THEN
	assert.NotEmpty(t, signer.Hash())
}