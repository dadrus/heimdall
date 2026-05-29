// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package pem

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	x509pkix "crypto/x509/pkix"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewCertificateStoreFromPEMBytes(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		pemBytes func(*testing.T) []byte
		assert   func(*testing.T, certStore, error)
	}{
		"creates certificate store": {
			pemBytes: func(t *testing.T) []byte {
				t.Helper()

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
					testsupport.WithValidity(time.Now(), 24*time.Hour),
					testsupport.WithSubjectPubKey(&intermediateKey.PublicKey, x509.ECDSAWithSHA384),
					testsupport.WithIsCA(),
				)
				require.NoError(t, err)

				pemBytes, err := pemx.BuildPEM(
					pemx.WithX509Certificate(intermediateCert),
					pemx.WithX509Certificate(rootCA.Certificate),
				)
				require.NoError(t, err)

				return pemBytes
			},
			assert: func(t *testing.T, cs certStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, cs, 2)
				assert.Equal(t, "PEM Test Intermediate CA", cs[0].Subject.CommonName)
				assert.Equal(t, "PEM Test Root CA", cs[1].Subject.CommonName)
			},
		},
		"returns configuration error if no certificate material is present": {
			pemBytes: func(t *testing.T) []byte {
				t.Helper()

				return nil
			},
			assert: func(t *testing.T, _ certStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "no certificate material present")
			},
		},
		"returns internal error for unsupported pem block type": {
			pemBytes: func(t *testing.T) []byte {
				t.Helper()

				privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)

				pemBytes, err := pemx.BuildPEM(pemx.WithECDSAPrivateKey(privateKey))
				require.NoError(t, err)

				return pemBytes
			},
			assert: func(t *testing.T, _ certStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrInternal)
				require.ErrorContains(t, err, "unsupported entry")
			},
		},
		"returns internal error for malformed certificate data": {
			pemBytes: func(t *testing.T) []byte {
				t.Helper()

				return []byte(`
-----BEGIN CERTIFICATE-----
MHcCAQEEIAcCM9VY6RRiUlz3UoywbT9yN9UlWEEWKIPqiA2D86pCoAoGCCqGSM49
AwEHoUQDQgAEPEmirqVF2KoNguFuh4GGyShM3OIZt/yD6WESlOvAJhJX6HZyOgFu
xijD/4gPFRBfs2GsfVZzSL9kH7HH0chB9w==
-----END CERTIFICATE-----
`)
			},
			assert: func(t *testing.T, _ certStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrInternal)
				require.ErrorContains(t, err, "failed to parse")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			cs, err := newCertificateStoreFromPEMBytes(tc.pemBytes(t))
			tc.assert(t, cs, err)
		})
	}
}

func TestCertStoreGetSecret(t *testing.T) {
	t.Parallel()

	cs := certStore{}

	secret, err := cs.getSecret(t.Context(), provider.Selector{})

	require.Error(t, err)
	require.ErrorIs(t, err, provider.ErrUnsupportedOperation)
	require.Nil(t, secret)
}

func TestCertStoreGetSecretSet(t *testing.T) {
	t.Parallel()

	cs := certStore{}

	secretSet, err := cs.getSecretSet(t.Context(), provider.Selector{})

	require.Error(t, err)
	require.ErrorIs(t, err, provider.ErrUnsupportedOperation)
	require.Nil(t, secretSet)
}

func TestCertStoreGetCertificateBundle(t *testing.T) {
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
		testsupport.WithValidity(time.Now(), 24*time.Hour),
		testsupport.WithSubjectPubKey(&intermediateKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithIsCA(),
	)
	require.NoError(t, err)

	cs := certStore{intermediateCert, rootCA.Certificate}

	bundle, err := cs.getCertificateBundle(t.Context(), provider.Selector{})

	require.NoError(t, err)
	require.NotNil(t, bundle)
	assert.Empty(t, bundle.Selector())
	assert.Equal(t, []*x509.Certificate{intermediateCert, rootCA.Certificate}, bundle.Certificates())
}

func TestCertStoreSameKind(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		other store
		want  bool
	}{
		"returns true for certificate store": {
			other: certStore{},
			want:  true,
		},
		"returns false for key store": {
			other: keyStore{},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			cs := certStore{}

			assert.Equal(t, tc.want, cs.sameKind(tc.other))
		})
	}
}