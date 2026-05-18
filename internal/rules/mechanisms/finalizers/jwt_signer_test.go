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

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		config *SignerConfig
		setup  func(t *testing.T, sm *secretsmocks.ManagerMock)
		assert func(t *testing.T, err error, signer *jwtSigner)
	}{
		"resolve secret fails": {
			config: &SignerConfig{Secret: config.Secret{Source: "foo", Selector: "bar"}},
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().ResolveSecret(mock.Anything, mock.Anything).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, _ *jwtSigner) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed resolving jwt signing secret")
			},
		},
		"successful configuration": {
			config: &SignerConfig{
				Name:   "foo",
				Secret: config.Secret{Source: "signer", Selector: "jwt/signing/2026-05"},
			},
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().ResolveSecret(mock.Anything, mock.Anything).Return(
					secrettypes.NewAsymmetricKeySecret("bar", "baz", privKey, nil),
					nil,
				)
				sm.EXPECT().Subscribe(mock.Anything, mock.Anything).Return(func() {}, nil)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, signer)
				assert.Equal(t, "foo", signer.iss)
				assert.NotEmpty(t, signer.Hash())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			sm := secretsmocks.NewManagerMock(t)
			tc.setup(t, sm)

			ko := keyregistrymocks.NewKeyObserverMock(t)
			ko.EXPECT().Notify(mock.Anything).Maybe()

			signer, err := newJWTSigner(t.Context(), tc.config, sm, ko)
			tc.assert(t, err, signer)
		})
	}
}

func TestJWTSignerSign(t *testing.T) {
	t.Parallel()

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	ko := keyregistrymocks.NewKeyObserverMock(t)
	ko.EXPECT().Notify(mock.Anything)

	sm := secretsmocks.NewManagerMock(t)
	sm.EXPECT().ResolveSecret(mock.Anything, mock.Anything).
		Return(
			secrettypes.NewAsymmetricKeySecret("bar", "baz", privKey, nil),
			nil,
		)
	sm.EXPECT().Subscribe(mock.Anything, mock.Anything).Return(func() {}, nil)

	signer, err := newJWTSigner(
		t.Context(),
		&SignerConfig{
			Name:   "foo",
			Secret: config.Secret{Source: "signer", Selector: "jwt/signing/2026-05"},
		},
		sm,
		ko,
	)
	require.NoError(t, err)

	rawToken, err := signer.Sign("alice", time.Minute, map[string]any{"scope": "test"})
	require.NoError(t, err)

	parsed, err := jwt.ParseSigned(rawToken, []jose.SignatureAlgorithm{jose.ES384})
	require.NoError(t, err)
	assert.Len(t, parsed.Headers, 1)
	assert.Equal(t, "baz", parsed.Headers[0].KeyID)
	assert.Equal(t, "foo", signer.iss)
}
