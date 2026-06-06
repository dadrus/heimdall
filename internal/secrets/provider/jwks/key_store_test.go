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

package jwks

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	x509pkix "crypto/x509/pkix"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewKeyStore(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		jwks   func(*testing.T) jose.JSONWebKeySet
		assert func(*testing.T, keyStore, error)
	}{
		"supports symmetric keys": {
			jwks: func(t *testing.T) jose.JSONWebKeySet {
				t.Helper()

				return jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:       []byte("0123456789abcdef"),
							KeyID:     "hmac-key",
							Algorithm: "HS256",
						},
					},
				}
			},
			assert: func(t *testing.T, ks keyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, ks, 1)

				secret, ok := ks[0].(provider.SymmetricKeySecret)
				require.True(t, ok)

				assert.Equal(t, "hmac-key", secret.Selector())
				assert.Equal(t, "hmac-key", secret.KeyID())
				assert.Equal(t, []byte("0123456789abcdef"), secret.Key())

				require.True(t, ok)
				assert.Equal(t, "HS256", secret.Algorithm())
			},
		},
		"supports rsa private keys": {
			jwks: func(t *testing.T) jose.JSONWebKeySet {
				t.Helper()

				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				return jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:   key,
							KeyID: "rsa-key",
						},
					},
				}
			},
			assert: func(t *testing.T, ks keyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, ks, 1)

				secret, ok := ks[0].(provider.AsymmetricKeySecret)
				require.True(t, ok)

				assert.Equal(t, "rsa-key", secret.Selector())
				assert.Equal(t, "rsa-key", secret.KeyID())
				assert.IsType(t, &rsa.PrivateKey{}, secret.PrivateKey())
				assert.Empty(t, secret.CertChain())
			},
		},
		"supports ec private keys": {
			jwks: func(t *testing.T) jose.JSONWebKeySet {
				t.Helper()

				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				return jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:   key,
							KeyID: "ec-key",
						},
					},
				}
			},
			assert: func(t *testing.T, ks keyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, ks, 1)

				secret, ok := ks[0].(provider.AsymmetricKeySecret)
				require.True(t, ok)

				assert.Equal(t, "ec-key", secret.Selector())
				assert.Equal(t, "ec-key", secret.KeyID())
				assert.IsType(t, &ecdsa.PrivateKey{}, secret.PrivateKey())
				assert.Empty(t, secret.CertChain())
			},
		},
		"supports ed25519 private keys": {
			jwks: func(t *testing.T) jose.JSONWebKeySet {
				t.Helper()

				_, key, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)

				return jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:   key,
							KeyID: "ed25519-key",
						},
					},
				}
			},
			assert: func(t *testing.T, ks keyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, ks, 1)

				secret, ok := ks[0].(provider.AsymmetricKeySecret)
				require.True(t, ok)

				assert.Equal(t, "ed25519-key", secret.Selector())
				assert.Equal(t, "ed25519-key", secret.KeyID())
				assert.IsType(t, ed25519.PrivateKey{}, secret.PrivateKey())
				assert.Empty(t, secret.CertChain())
			},
		},
		"supports mixed keys": {
			jwks: func(t *testing.T) jose.JSONWebKeySet {
				t.Helper()

				rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				return jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:   rsaKey,
							KeyID: "rsa-key",
						},
						{
							Key:       []byte("0123456789abcdef"),
							KeyID:     "hmac-key",
							Algorithm: "HS256",
						},
						{
							Key:   ecKey,
							KeyID: "ec-key",
						},
					},
				}
			},
			assert: func(t *testing.T, ks keyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, ks, 3)

				assert.Equal(t, "rsa-key", ks[0].Selector())
				assert.Equal(t, "hmac-key", ks[1].Selector())
				assert.Equal(t, "ec-key", ks[2].Selector())
			},
		},
		"returns configuration error for missing kid": {
			jwks: func(t *testing.T) jose.JSONWebKeySet {
				t.Helper()

				return jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key: []byte("0123456789abcdef"),
						},
					},
				}
			},
			assert: func(t *testing.T, _ keyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "missing required kid")
			},
		},
		"returns configuration error for blank kid": {
			jwks: func(t *testing.T) jose.JSONWebKeySet {
				t.Helper()

				return jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:   []byte("0123456789abcdef"),
							KeyID: "   ",
						},
					},
				}
			},
			assert: func(t *testing.T, _ keyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "missing required kid")
			},
		},
		"returns configuration error for duplicate kid": {
			jwks: func(t *testing.T) jose.JSONWebKeySet {
				t.Helper()

				return jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:   []byte("0123456789abcdef"),
							KeyID: "duplicate",
						},
						{
							Key:   []byte("fedcba9876543210"),
							KeyID: "duplicate",
						},
					},
				}
			},
			assert: func(t *testing.T, _ keyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "duplicate jwk kid 'duplicate' found")
			},
		},
		"returns configuration error for too short symmetric key": {
			jwks: func(t *testing.T) jose.JSONWebKeySet {
				t.Helper()

				return jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:   []byte("too-short"),
							KeyID: "short-key",
						},
					},
				}
			},
			assert: func(t *testing.T, _ keyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "contains key material shorter than 16 bytes")
			},
		},
		"returns configuration error for public key": {
			jwks: func(t *testing.T) jose.JSONWebKeySet {
				t.Helper()

				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				return jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:   &key.PublicKey,
							KeyID: "public-key",
						},
					},
				}
			},
			assert: func(t *testing.T, _ keyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "unsupported jwk key material")
			},
		},
		"returns configuration error if no keys are present": {
			jwks: func(t *testing.T) jose.JSONWebKeySet {
				t.Helper()

				return jose.JSONWebKeySet{}
			},
			assert: func(t *testing.T, _ keyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "no key material present")
			},
		},
		"supports rsa private keys with self-signed certificate": {
			jwks: func(t *testing.T) jose.JSONWebKeySet {
				t.Helper()

				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				cert, err := testsupport.NewCertificateBuilder(
					testsupport.WithSubject(x509pkix.Name{CommonName: "rsa-key"}),
					testsupport.WithSubjectPubKey(&key.PublicKey, x509.SHA256WithRSA),
					testsupport.WithSignaturePrivKey(key),
					testsupport.WithSelfSigned(),
					testsupport.WithValidity(time.Now().Add(-time.Hour), 2*time.Hour),
				).Build()
				require.NoError(t, err)

				return jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:          key,
							KeyID:        "rsa-key",
							Certificates: []*x509.Certificate{cert},
						},
					},
				}
			},
			assert: func(t *testing.T, ks keyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, ks, 1)

				secret, ok := ks[0].(provider.AsymmetricKeySecret)
				require.True(t, ok)

				assert.Equal(t, "rsa-key", secret.Selector())
				assert.Equal(t, "rsa-key", secret.KeyID())
				assert.IsType(t, &rsa.PrivateKey{}, secret.PrivateKey())
				require.Len(t, secret.CertChain(), 1)
				assert.Equal(t, "rsa-key", secret.CertChain()[0].Subject.CommonName)
			},
		},
		"returns configuration error for malformed certificate chain": {
			jwks: func(t *testing.T) jose.JSONWebKeySet {
				t.Helper()

				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				cert, err := testsupport.NewCertificateBuilder(
					testsupport.WithSubject(x509pkix.Name{CommonName: "other-key"}),
					testsupport.WithSubjectPubKey(&otherKey.PublicKey, x509.SHA256WithRSA),
					testsupport.WithSignaturePrivKey(otherKey),
					testsupport.WithSelfSigned(),
					testsupport.WithValidity(time.Now().Add(-time.Hour), 2*time.Hour),
				).Build()
				require.NoError(t, err)

				return jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:          key,
							KeyID:        "rsa-key",
							Certificates: []*x509.Certificate{cert},
						},
					},
				}
			},
			assert: func(t *testing.T, _ keyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "malformed certificate chain for kid 'rsa-key'")
			},
		},
		"returns configuration error for invalid certificate chain": {
			jwks: func(t *testing.T) jose.JSONWebKeySet {
				t.Helper()

				leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)

				ca, err := testsupport.NewRootCA("root CA", -1*time.Hour)
				require.NoError(t, err)

				leaf, err := testsupport.NewCertificateBuilder(
					testsupport.WithSubject(x509pkix.Name{CommonName: "other-key"}),
					testsupport.WithSubjectPubKey(&leafKey.PublicKey, x509.ECDSAWithSHA384),
					testsupport.WithSignaturePrivKey(leafKey),
					testsupport.WithIssuer(ca.PrivKey, ca.Certificate),
					testsupport.WithValidity(time.Now().Add(-time.Hour), 2*time.Hour),
				).Build()
				require.NoError(t, err)

				return jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:          leafKey,
							KeyID:        "leaf-key",
							Certificates: []*x509.Certificate{leaf, ca.Certificate},
						},
					},
				}
			},
			assert: func(t *testing.T, _ keyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "invalid certificate chain for kid 'leaf-key'")
			},
		},
		"supports keys with full certificate chain": {
			jwks: func(t *testing.T) jose.JSONWebKeySet {
				t.Helper()

				leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)

				issCAKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)

				rootCA, err := testsupport.NewRootCA("Root CA", 1*time.Hour)
				require.NoError(t, err)

				issCACert, err := rootCA.IssueCertificate(
					testsupport.WithSubject(x509pkix.Name{
						CommonName:   "Iss CA",
						Organization: []string{"Test"},
						Country:      []string{"EU"},
					}),
					testsupport.WithIsCA(),
					testsupport.WithValidity(time.Now(), time.Hour*24),
					testsupport.WithSubjectPubKey(&issCAKey.PublicKey, x509.ECDSAWithSHA384),
				)
				require.NoError(t, err)

				issCA := testsupport.NewCA(issCAKey, issCACert)
				leaf, err := issCA.IssueCertificate(
					testsupport.WithSubject(x509pkix.Name{CommonName: "ee-key"}),
					testsupport.WithSubjectPubKey(&leafKey.PublicKey, x509.ECDSAWithSHA384),
					testsupport.WithSignaturePrivKey(leafKey),
					testsupport.WithIssuer(issCA.PrivKey, issCA.Certificate),
					testsupport.WithValidity(time.Now().Add(-time.Hour), 2*time.Hour),
				)
				require.NoError(t, err)

				return jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:          leafKey,
							KeyID:        "leaf-key",
							Certificates: []*x509.Certificate{leaf, rootCA.Certificate, issCA.Certificate},
						},
					},
				}
			},
			assert: func(t *testing.T, ks keyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, ks, 1)

				secret, ok := ks[0].(provider.AsymmetricKeySecret)
				require.True(t, ok)

				assert.Equal(t, "leaf-key", secret.Selector())
				assert.Equal(t, "leaf-key", secret.KeyID())
				assert.IsType(t, &ecdsa.PrivateKey{}, secret.PrivateKey())
				require.Len(t, secret.CertChain(), 3)
				assert.Equal(t, "ee-key", secret.CertChain()[0].Subject.CommonName)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			ks, err := newKeyStore(tc.jwks(t))
			tc.assert(t, ks, err)
		})
	}
}

func TestKeyStoreGetSecret(t *testing.T) {
	t.Parallel()

	ks := keyStore{
		provider.NewSymmetricKeySecret("first", "first", "HS256", []byte("0123456789abcdef")),
		provider.NewSymmetricKeySecret("second", "second", "HS384", []byte("0123456789abcdef0123456789abcdef")),
	}

	for uc, tc := range map[string]struct {
		ks       keyStore
		selector provider.Selector
		assert   func(*testing.T, provider.Secret, error)
	}{
		"returns first entry for empty selector": {
			ks: ks,
			assert: func(t *testing.T, secret provider.Secret, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, secret)
				assert.Equal(t, "first", secret.Selector())
			},
		},
		"returns entry for existing selector": {
			ks:       ks,
			selector: provider.Selector{Value: "second"},
			assert: func(t *testing.T, secret provider.Secret, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, secret)
				assert.Equal(t, "second", secret.Selector())
			},
		},
		"returns error for missing selector": {
			ks:       ks,
			selector: provider.Selector{Value: "missing"},
			assert: func(t *testing.T, _ provider.Secret, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrSecretNotFound)
			},
		},
		"returns error if store is empty": {
			ks: keyStore{},
			assert: func(t *testing.T, _ provider.Secret, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrSecretNotFound)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			secret, err := tc.ks.getSecret(t.Context(), tc.selector)
			tc.assert(t, secret, err)
		})
	}
}

func TestKeyStoreGetSecretSet(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		ks     keyStore
		assert func(*testing.T, []provider.Secret, error)
	}{
		"returns all entries": {
			ks: keyStore{
				provider.NewSymmetricKeySecret("first", "first", "HS256", []byte("0123456789abcdef")),
				provider.NewSymmetricKeySecret("second", "second", "HS384", []byte("0123456789abcdef0123456789abcdef")),
			},
			assert: func(t *testing.T, secrets []provider.Secret, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, secrets, 2)
				assert.Equal(t, "first", secrets[0].Selector())
				assert.Equal(t, "second", secrets[1].Selector())
			},
		},
		"returns error if store is empty": {
			ks: keyStore{},
			assert: func(t *testing.T, secrets []provider.Secret, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrSecretSetNotFound)
				require.Nil(t, secrets)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			secrets, err := tc.ks.getSecretSet(t.Context(), provider.Selector{Value: "ignored"})
			tc.assert(t, secrets, err)
		})
	}
}

func TestKeyStoreGetCertificateBundle(t *testing.T) {
	t.Parallel()

	ks := keyStore{}

	bundle, err := ks.getCertificateBundle(t.Context(), provider.Selector{})

	require.Error(t, err)
	require.ErrorIs(t, err, provider.ErrUnsupportedOperation)
	require.Nil(t, bundle)
}
