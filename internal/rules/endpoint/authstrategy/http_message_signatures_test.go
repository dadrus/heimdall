// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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

package authstrategy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	x509pkix "crypto/x509/pkix"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/dadrus/httpsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	keyregistrymocks "github.com/dadrus/heimdall/internal/keyregistry/mocks"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestHTTPMessageSignaturesInit(t *testing.T) {
	t.Parallel()

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.SecretHandleMock)
		assert func(t *testing.T, err error, conf *HTTPMessageSignatures)
	}{
		"starting resolver fails": {
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, _ *secretsmocks.SecretHandleMock) {
				t.Helper()

				sr.EXPECT().
					Secret(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.Anything,
					).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, hms *HTTPMessageSignatures) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed resolving secret")

				assert.Empty(t, hms.Hash())
				assert.Nil(t, hms.informer)
			},
		},
		"successful configuration": {
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.SecretHandleMock) {
				t.Helper()

				secret := secrettypes.NewAsymmetricKeySecret("bar", "baz", privKey, nil)

				sr.EXPECT().
					Secret(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.Anything,
					).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(context.Background(), secret)
						require.NoError(t, err)

						return true
					}))

				handle.EXPECT().
					Get(mock.Anything).
					Return(secret, true)
			},
			assert: func(t *testing.T, err error, hms *HTTPMessageSignatures) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEmpty(t, hms.Hash())

				_, ok := hms.informer.Get(t.Context())
				require.True(t, ok)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			secret := config.Secret{Source: "foo", Selector: "bar"}

			sr := secretsmocks.NewResolverMock(t)
			handle := secretsmocks.NewSecretHandleMock(t)

			tc.setup(t, sr, handle)

			reg := keyregistrymocks.NewRegistryMock(t)
			reg.EXPECT().Notify(mock.Anything).Maybe()

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().SecretResolver().Return(sr)
			appCtx.EXPECT().KeyRegistry().Maybe().Return(reg)

			conf := &HTTPMessageSignatures{
				Signer:     SignerConfig{Secret: secret},
				Components: []string{"@method"},
			}

			err := conf.init(t.Context(), appCtx)

			tc.assert(t, err, conf)
		})
	}
}

func TestHTTPMessageSignaturesHash(t *testing.T) {
	t.Parallel()

	secret := secrettypes.NewAsymmetricKeySecret("bar", "baz", nil, nil)

	conf1 := &HTTPMessageSignatures{
		Signer:     SignerConfig{Name: "foo"},
		Components: []string{"@method"},
		TTL:        new(time.Duration),
	}
	*conf1.TTL = time.Hour
	conf1.updateHash(secret)

	conf2 := &HTTPMessageSignatures{
		Label:      "label",
		Signer:     SignerConfig{Name: "bar"},
		Components: []string{"@status"},
		TTL:        new(time.Duration),
	}
	*conf2.TTL = time.Hour
	conf2.updateHash(secret)

	conf3 := &HTTPMessageSignatures{
		Signer:     SignerConfig{Name: "baz"},
		Components: []string{"@method"},
		TTL:        new(time.Duration),
	}
	*conf3.TTL = time.Hour
	conf3.updateHash(secret)

	hash1 := conf1.Hash()
	hash2 := conf2.Hash()
	hash3 := conf3.Hash()

	assert.NotEqual(t, hash1, hash2)
	assert.NotEqual(t, hash1, hash3)
	assert.NotEmpty(t, hash1)
}

func TestHTTPMessageSignaturesApply(t *testing.T) {
	t.Parallel()

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	secret := secrettypes.NewAsymmetricKeySecret("bar", "kid-1", privKey, nil)

	sr := secretsmocks.NewResolverMock(t)
	handle := secretsmocks.NewSecretHandleMock(t)

	sr.EXPECT().
		Secret(
			mock.Anything,
			secrets.Reference{Source: "foo", Selector: "bar"},
			mock.Anything,
		).
		Return(handle, nil)

	handle.EXPECT().
		OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
			err := cb(context.Background(), secret)
			require.NoError(t, err)

			return true
		}))

	handle.EXPECT().
		Get(mock.Anything).
		Return(secret, true)

	reg := keyregistrymocks.NewRegistryMock(t)
	reg.EXPECT().Notify(mock.Anything).Maybe()

	appCtx := app.NewContextMock(t)
	appCtx.EXPECT().SecretResolver().Return(sr)
	appCtx.EXPECT().KeyRegistry().Maybe().Return(reg)

	conf := &HTTPMessageSignatures{
		Signer:     SignerConfig{Secret: config.Secret{Source: "foo", Selector: "bar"}},
		Components: []string{"@method"},
	}

	err = conf.init(t.Context(), appCtx)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)

	require.NoError(t, conf.Apply(req))
	assert.NotEmpty(t, req.Header.Get("Signature"))
}

func TestHTTPMessageSignaturesCreateSigner(t *testing.T) {
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
		secret     secrets.Secret
		components []string
		assert     func(t *testing.T, err error, signer httpsig.Signer)
	}{
		"secret not suitable for signing": {
			secret:     secrettypes.NewStringSecret("bar", "baz"),
			components: []string{"@method"},
			assert: func(t *testing.T, err error, _ httpsig.Signer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "not suitable for signing")
			},
		},
		"certificate validation error": {
			secret: secrettypes.NewAsymmetricKeySecret(
				"kid1",
				"kid1",
				privateKey,
				[]*x509.Certificate{leafCert, rootCA.Certificate},
			),
			components: []string{"@method"},
			assert: func(t *testing.T, err error, _ httpsig.Signer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "unknown authority")
			},
		},
		"unsupported algorithm": {
			secret:     secrettypes.NewAsymmetricKeySecret("unsupported", "unsupported", unsupportedSigner{}, nil),
			components: []string{"@method"},
			assert: func(t *testing.T, err error, _ httpsig.Signer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, errUnsupportedAlgorithm)
			},
		},
		"fails to create signer": {
			secret:     secrettypes.NewAsymmetricKeySecret("kid1", "kid1", privateKey, nil),
			components: []string{"@foo"},
			assert: func(t *testing.T, err error, _ httpsig.Signer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed creating signer")
			},
		},
		"successful configuration": {
			secret: secrettypes.NewAsymmetricKeySecret(
				"kid1",
				"kid1",
				privateKey,
				[]*x509.Certificate{leafCert, intermediateCert, rootCA.Certificate},
			),
			components: []string{"@method"},
			assert: func(t *testing.T, err error, sig httpsig.Signer) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, sig)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			hms := &HTTPMessageSignatures{
				Components: tc.components,
				Label:      "label",
			}

			signer, err := hms.createSigner(tc.secret)

			tc.assert(t, err, signer)
		})
	}
}

type unsupportedSigner struct{}

func (s unsupportedSigner) Public() crypto.PublicKey {
	return nil
}

func (s unsupportedSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, assert.AnError
}

func TestToHTTPSigKey(t *testing.T) {
	t.Parallel()

	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec
	require.NoError(t, err)

	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rsa3072, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)

	rsa4096, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	ecdsa224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	ecdsa256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecdsa384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	ecdsa521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	_, ed25519PrKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		secret secrets.AsymmetricKeySecret
		alg    httpsig.SignatureAlgorithm
		err    error
	}{
		"rsa1024": {
			secret: secrettypes.NewAsymmetricKeySecret("rsa", "rsa", rsa1024, nil),
			err:    errUnsupportedKeySize,
		},
		"rsa2048": {
			secret: secrettypes.NewAsymmetricKeySecret("rsa", "rsa", rsa2048, nil),
			alg:    httpsig.RsaPssSha256,
		},
		"rsa3072": {
			secret: secrettypes.NewAsymmetricKeySecret("rsa", "rsa", rsa3072, nil),
			alg:    httpsig.RsaPssSha384,
		},
		"rsa4096": {
			secret: secrettypes.NewAsymmetricKeySecret("rsa", "rsa", rsa4096, nil),
			alg:    httpsig.RsaPssSha512,
		},
		"p224": {
			secret: secrettypes.NewAsymmetricKeySecret("ecdsa", "ecdsa", ecdsa224, nil),
			err:    errUnsupportedKeySize,
		},
		"p256": {
			secret: secrettypes.NewAsymmetricKeySecret("ecdsa", "ecdsa", ecdsa256, nil),
			alg:    httpsig.EcdsaP256Sha256,
		},
		"p384": {
			secret: secrettypes.NewAsymmetricKeySecret("ecdsa", "ecdsa", ecdsa384, nil),
			alg:    httpsig.EcdsaP384Sha384,
		},
		"p521": {
			secret: secrettypes.NewAsymmetricKeySecret("ecdsa", "ecdsa", ecdsa521, nil),
			alg:    httpsig.EcdsaP521Sha512,
		},
		"ed25519": {
			secret: secrettypes.NewAsymmetricKeySecret("ed25519", "ed25519", ed25519PrKey, nil),
			alg:    httpsig.Ed25519,
		},
		"unsupported": {
			secret: secrettypes.NewAsymmetricKeySecret("unsupported", "unsupported", unsupportedSigner{}, nil),
			err:    errUnsupportedAlgorithm,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			key, err := toHTTPSigKey(tc.secret)

			if tc.err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.alg, key.Algorithm)
			assert.Equal(t, tc.secret.KeyID(), key.KeyID)
			assert.Equal(t, tc.secret.PrivateKey(), key.Key)
		})
	}
}
