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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/watcher/mocks"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewJWTSigner(t *testing.T) {
	t.Parallel()

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

	ecdsaPrivKey4, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	cert4, err := testsupport.NewCertificateBuilder(testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert 4",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&ecdsaPrivKey4.PublicKey, x509.ECDSAWithSHA512),
		testsupport.WithSelfSigned(),
		testsupport.WithSignaturePrivKey(ecdsaPrivKey4)).
		Build()
	require.NoError(t, err)

	ecdsaPrivKey5, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	cert5, err := testsupport.NewCertificateBuilder(testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert 5",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&ecdsaPrivKey5.PublicKey, x509.ECDSAWithSHA512),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
		testsupport.WithSelfSigned(),
		testsupport.WithSignaturePrivKey(ecdsaPrivKey5)).
		Build()
	require.NoError(t, err)

	rootCA, err := testsupport.NewRootCA("Test Root CA 1", time.Hour*24)
	require.NoError(t, err)

	// INT CA
	intCAPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	intCACert, err := rootCA.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test Int CA 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithIsCA(),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&intCAPrivKey.PublicKey, x509.ECDSAWithSHA384))
	require.NoError(t, err)

	intCA := testsupport.NewCA(intCAPrivKey, intCACert)

	// EE CERTS
	ee1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	cert6, err := intCA.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&ee1PrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
	require.NoError(t, err)

	pemBytes, err := pemx.BuildPEM(
		pemx.WithRSAPrivateKey(rsaPrivKey1, pemx.WithHeader("X-Key-ID", "key1")),
		pemx.WithRSAPrivateKey(rsaPrivKey2, pemx.WithHeader("X-Key-ID", "key2")),
		pemx.WithRSAPrivateKey(rsaPrivKey3, pemx.WithHeader("X-Key-ID", "key3")),
		pemx.WithECDSAPrivateKey(ecdsaPrivKey1, pemx.WithHeader("X-Key-ID", "key4")),
		pemx.WithECDSAPrivateKey(ecdsaPrivKey2, pemx.WithHeader("X-Key-ID", "key5")),
		pemx.WithECDSAPrivateKey(ecdsaPrivKey3, pemx.WithHeader("X-Key-ID", "key6")),
		pemx.WithECDSAPrivateKey(ecdsaPrivKey4, pemx.WithHeader("X-Key-ID", "missing_key_usage")),
		pemx.WithX509Certificate(cert4),
		pemx.WithECDSAPrivateKey(ecdsaPrivKey5, pemx.WithHeader("X-Key-ID", "self_signed")),
		pemx.WithX509Certificate(cert5),
		pemx.WithECDSAPrivateKey(ee1PrivKey, pemx.WithHeader("X-Key-ID", "key7")),
		pemx.WithX509Certificate(cert6),
		pemx.WithX509Certificate(intCACert),
		pemx.WithX509Certificate(rootCA.Certificate),
	)
	require.NoError(t, err)

	testDir := t.TempDir()
	keyFile, err := os.Create(filepath.Join(testDir, "keys.pem"))
	require.NoError(t, err)

	_, err = keyFile.Write(pemBytes)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		config func(t *testing.T, wm *mocks.WatcherMock) *SignerConfig
		assert func(t *testing.T, err error, signer *jwtSigner)
	}{
		"without configuration": {
			config: func(t *testing.T, _ *mocks.WatcherMock) *SignerConfig {
				t.Helper()

				return &SignerConfig{}
			},
			assert: func(t *testing.T, err error, _ *jwtSigner) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "failed loading keystore")
			},
		},
		"no key id configured": {
			config: func(t *testing.T, wm *mocks.WatcherMock) *SignerConfig {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)

				return &SignerConfig{Name: "foo", KeyStore: KeyStore{Path: keyFile.Name()}}
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, rsaPrivKey1, signer.key)
				assert.Equal(t, "key1", signer.jwk.KeyID)
				assert.Equal(t, string(jose.PS256), signer.jwk.Algorithm)
				assert.Empty(t, signer.activeCertificateChain())
			},
		},
		"with key id configured": {
			config: func(t *testing.T, wm *mocks.WatcherMock) *SignerConfig {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)

				return &SignerConfig{Name: "foo", KeyStore: KeyStore{Path: keyFile.Name()}, KeyID: "key2"}
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, rsaPrivKey2, signer.key)
				assert.Equal(t, "key2", signer.jwk.KeyID)
				assert.Equal(t, string(jose.PS384), signer.jwk.Algorithm)
				assert.Empty(t, signer.activeCertificateChain())
			},
		},
		"with error while retrieving key from key store": {
			config: func(t *testing.T, _ *mocks.WatcherMock) *SignerConfig {
				t.Helper()

				return &SignerConfig{Name: "foo", KeyStore: KeyStore{Path: keyFile.Name()}, KeyID: "baz"}
			},
			assert: func(t *testing.T, err error, _ *jwtSigner) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, keystore.ErrNoSuchKey)
			},
		},
		"with rsa 2048 key": {
			config: func(t *testing.T, wm *mocks.WatcherMock) *SignerConfig {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)

				return &SignerConfig{Name: "foo", KeyStore: KeyStore{Path: keyFile.Name()}, KeyID: "key1"}
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, rsaPrivKey1, signer.key)
				assert.Equal(t, "key1", signer.jwk.KeyID)
				assert.Equal(t, string(jose.PS256), signer.jwk.Algorithm)
				assert.Empty(t, signer.activeCertificateChain())
			},
		},
		"with rsa 3072 key": {
			config: func(t *testing.T, wm *mocks.WatcherMock) *SignerConfig {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)

				return &SignerConfig{Name: "foo", KeyStore: KeyStore{Path: keyFile.Name()}, KeyID: "key2"}
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, rsaPrivKey2, signer.key)
				assert.Equal(t, "key2", signer.jwk.KeyID)
				assert.Equal(t, string(jose.PS384), signer.jwk.Algorithm)
				assert.Empty(t, signer.activeCertificateChain())
			},
		},
		"with rsa 4096 key": {
			config: func(t *testing.T, wm *mocks.WatcherMock) *SignerConfig {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)

				return &SignerConfig{Name: "foo", KeyStore: KeyStore{Path: keyFile.Name()}, KeyID: "key3"}
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, rsaPrivKey3, signer.key)
				assert.Equal(t, "key3", signer.jwk.KeyID)
				assert.Equal(t, string(jose.PS512), signer.jwk.Algorithm)
				assert.Empty(t, signer.activeCertificateChain())
			},
		},
		"with P256 ecdsa key": {
			config: func(t *testing.T, wm *mocks.WatcherMock) *SignerConfig {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)

				return &SignerConfig{Name: "foo", KeyStore: KeyStore{Path: keyFile.Name()}, KeyID: "key4"}
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, ecdsaPrivKey1, signer.key)
				assert.Equal(t, "key4", signer.jwk.KeyID)
				assert.Equal(t, string(jose.ES256), signer.jwk.Algorithm)
				assert.Empty(t, signer.activeCertificateChain())
			},
		},
		"with P384 ecdsa key": {
			config: func(t *testing.T, wm *mocks.WatcherMock) *SignerConfig {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)

				return &SignerConfig{Name: "foo", KeyStore: KeyStore{Path: keyFile.Name()}, KeyID: "key5"}
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, ecdsaPrivKey2, signer.key)
				assert.Equal(t, "key5", signer.jwk.KeyID)
				assert.Equal(t, string(jose.ES384), signer.jwk.Algorithm)
				assert.Empty(t, signer.activeCertificateChain())
			},
		},
		"with P512 ecdsa key": {
			config: func(t *testing.T, wm *mocks.WatcherMock) *SignerConfig {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)

				return &SignerConfig{Name: "foo", KeyStore: KeyStore{Path: keyFile.Name()}, KeyID: "key6"}
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, ecdsaPrivKey3, signer.key)
				assert.Equal(t, "key6", signer.jwk.KeyID)
				assert.Equal(t, string(jose.ES512), signer.jwk.Algorithm)
				assert.Empty(t, signer.activeCertificateChain())
			},
		},
		"with not existing key store": {
			config: func(t *testing.T, _ *mocks.WatcherMock) *SignerConfig {
				t.Helper()

				return &SignerConfig{Name: "foo", KeyStore: KeyStore{Path: "/does/not/exist"}}
			},
			assert: func(t *testing.T, err error, _ *jwtSigner) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed to get information about")
			},
		},
		"with certificate, which cannot be used for signature due to missing key usage": {
			config: func(t *testing.T, _ *mocks.WatcherMock) *SignerConfig {
				t.Helper()

				return &SignerConfig{
					Name:     "foo",
					KeyStore: KeyStore{Path: keyFile.Name()},
					KeyID:    "missing_key_usage",
				}
			},
			assert: func(t *testing.T, err error, _ *jwtSigner) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "missing key usage: DigitalSignature")
			},
		},
		"with self-signed certificate usable for JWT signing": {
			config: func(t *testing.T, wm *mocks.WatcherMock) *SignerConfig {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)

				return &SignerConfig{
					Name:     "foo",
					KeyStore: KeyStore{Path: keyFile.Name()},
					KeyID:    "self_signed",
				}
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, ecdsaPrivKey5, signer.key)
				assert.Equal(t, "self_signed", signer.jwk.KeyID)
				assert.Equal(t, string(jose.ES512), signer.jwk.Algorithm)
				assert.Equal(t, []*x509.Certificate{cert5}, signer.activeCertificateChain())
			},
		},
		"with usable certificate including a full cert chain": {
			config: func(t *testing.T, wm *mocks.WatcherMock) *SignerConfig {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)

				return &SignerConfig{
					Name:     "foo",
					KeyStore: KeyStore{Path: keyFile.Name()},
					KeyID:    "key7",
				}
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.Equal(t, ee1PrivKey, signer.key)
				assert.Equal(t, "key7", signer.jwk.KeyID)
				assert.Equal(t, string(jose.ES384), signer.jwk.Algorithm)
				assert.Equal(t, []*x509.Certificate{cert6, intCACert, rootCA.Certificate}, signer.activeCertificateChain())
			},
		},
		"fails due to error while registering with file watcher": {
			config: func(t *testing.T, wm *mocks.WatcherMock) *SignerConfig {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(errors.New("test error"))

				return &SignerConfig{
					Name:     "foo",
					KeyStore: KeyStore{Path: keyFile.Name()},
					KeyID:    "self_signed",
				}
			},
			assert: func(t *testing.T, err error, _ *jwtSigner) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test error")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			wm := mocks.NewWatcherMock(t)
			signer, err := newJWTSigner(tc.config(t, wm), wm)

			// THEN
			tc.assert(t, err, signer)
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

	for uc, tc := range map[string]struct {
		signer *jwtSigner
		claims map[string]any
		assert func(t *testing.T, err error, rawJWT string, signer *jwtSigner, claims map[string]any)
	}{
		"sign with rsa": {
			signer: &jwtSigner{
				iss: "foo",
				key: rsaPrivKey1,
				jwk: jose.JSONWebKey{KeyID: "bar", Algorithm: string(jose.RS256)},
			},
			claims: map[string]any{"baz": "zab", "bla": "foo"},
			assert: func(t *testing.T, err error, rawJWT string, signer *jwtSigner, claims map[string]any) {
				t.Helper()

				require.NoError(t, err)
				validateTestJWT(t, rawJWT, signer, subjectID, ttl, claims)
			},
		},
		"sign with ecdsa": {
			signer: &jwtSigner{
				iss: "foo",
				key: ecdsaPrivKey1,
				jwk: jose.JSONWebKey{KeyID: "bar", Algorithm: string(jose.ES256)},
			},
			claims: map[string]any{"baz": "zab", "bla": "foo"},
			assert: func(t *testing.T, err error, rawJWT string, signer *jwtSigner, claims map[string]any) {
				t.Helper()

				require.NoError(t, err)
				validateTestJWT(t, rawJWT, signer, subjectID, ttl, claims)
			},
		},
		"sign claims, which contain JWT specific claims": {
			signer: &jwtSigner{
				iss: "foo",
				key: ecdsaPrivKey1,
				jwk: jose.JSONWebKey{KeyID: "bar", Algorithm: string(jose.ES256)},
			},
			claims: map[string]any{"iss": "bar"},
			assert: func(t *testing.T, err error, rawJWT string, signer *jwtSigner, claims map[string]any) {
				t.Helper()

				require.NoError(t, err)
				claims["iss"] = signer.iss
				validateTestJWT(t, rawJWT, signer, subjectID, ttl, claims)
			},
		},
		"sign with unsupported algorithm": {
			signer: &jwtSigner{
				iss: "foo",
				key: rsaPrivKey1,
				jwk: jose.JSONWebKey{KeyID: "bar", Algorithm: "foobar"},
			},
			claims: map[string]any{"baz": "zab", "bla": "foo"},
			assert: func(t *testing.T, err error, _ string, _ *jwtSigner, _ map[string]any) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "JWT signer")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
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

	var jwtClaims map[string]any

	require.Equal(t, 2, strings.Count(rawJWT, "."))

	token, err := jwt.ParseSigned(rawJWT, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(signer.jwk.Algorithm)})
	require.NoError(t, err)

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
	assert.GreaterOrEqual(t, float64(now), iat)

	assert.InDelta(t, iat, nbf, 0.00)
	assert.InDelta(t, exp-ttl.Seconds(), nbf, 0.00)

	for k, v := range customClaims {
		assert.Contains(t, jwtClaims, k)
		assert.Equal(t, v, jwtClaims[k])
	}
}

func TestJWTSignerHash(t *testing.T) {
	t.Parallel()

	// GIVEN
	signer := &jwtSigner{iss: "foo", jwk: jose.JSONWebKey{KeyID: "bar", Algorithm: "baz"}}

	// WHEN
	hash1 := signer.Hash()
	hash2 := signer.Hash()

	// THEN
	assert.NotEmpty(t, hash1)
	assert.Equal(t, hash1, hash2)
}

func TestJwtSignerKeys(t *testing.T) {
	t.Parallel()

	// GIVEN
	privKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	testDir := t.TempDir()
	keyFile, err := os.Create(filepath.Join(testDir, "keys.pem"))
	require.NoError(t, err)

	pemBytes, err := pemx.BuildPEM(
		pemx.WithRSAPrivateKey(privKey1, pemx.WithHeader("X-Key-ID", "key1")),
		pemx.WithECDSAPrivateKey(privKey2, pemx.WithHeader("X-Key-ID", "key2")),
	)
	require.NoError(t, err)

	_, err = keyFile.Write(pemBytes)
	require.NoError(t, err)

	fw := mocks.NewWatcherMock(t)
	fw.EXPECT().Add(keyFile.Name(), mock.Anything).Return(nil)

	signer, err := newJWTSigner(
		&SignerConfig{KeyStore: KeyStore{Path: keyFile.Name()}},
		fw,
	)
	require.NoError(t, err)

	// WHEN
	keys := signer.Keys()

	// THEN
	require.Len(t, keys, 2)

	assert.Equal(t, "PS256", keys[0].Algorithm)
	assert.Equal(t, "ES256", keys[1].Algorithm)
}

func TestJWTSignerOnChanged(t *testing.T) {
	t.Parallel()

	// GIVEN
	testDir := t.TempDir()

	privKey1, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	privKey2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cert1, err := testsupport.NewCertificateBuilder(testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&privKey1.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSelfSigned(),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
		testsupport.WithSignaturePrivKey(privKey1)).
		Build()
	require.NoError(t, err)

	cert2, err := testsupport.NewCertificateBuilder(testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&privKey2.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSelfSigned(),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
		testsupport.WithSignaturePrivKey(privKey2)).
		Build()
	require.NoError(t, err)

	pemBytes1, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(privKey1, pemx.WithHeader("X-Key-ID", "key1")),
		pemx.WithX509Certificate(cert1),
	)
	require.NoError(t, err)

	pemBytes2, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(privKey2, pemx.WithHeader("X-Key-ID", "key1")),
		pemx.WithX509Certificate(cert2),
	)
	require.NoError(t, err)

	pemFile, err := os.Create(filepath.Join(testDir, "keystore.pem"))
	require.NoError(t, err)

	_, err = pemFile.Write(pemBytes1)
	require.NoError(t, err)

	signer := &jwtSigner{path: pemFile.Name(), keyID: "key1"}
	err = signer.load()
	require.NoError(t, err)

	require.Equal(t, cert1, signer.jwk.Certificates[0])
	require.Equal(t, privKey1, signer.key)

	// WHEN
	_, err = pemFile.Seek(0, 0)
	require.NoError(t, err)

	_, err = pemFile.Write(pemBytes2)
	require.NoError(t, err)

	signer.OnChanged(log.Logger)

	// THEN
	require.Equal(t, cert2, signer.jwk.Certificates[0])
	require.Equal(t, privKey2, signer.key)

	// WHEN
	err = os.Truncate(pemFile.Name(), 0)
	require.NoError(t, err)

	signer.OnChanged(log.Logger)

	// THEN
	require.Equal(t, cert2, signer.jwk.Certificates[0])
	require.Equal(t, privKey2, signer.key)
}
