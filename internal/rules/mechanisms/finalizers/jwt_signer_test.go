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

	"github.com/dadrus/heimdall/internal/keyregistry"
	mocks2 "github.com/dadrus/heimdall/internal/keyregistry/mocks"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/watcher/mocks"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
	mock2 "github.com/dadrus/heimdall/internal/x/testsupport/mock"
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
		config     SignerConfig
		setupMocks func(t *testing.T, wm *mocks.WatcherMock, kom *mocks2.KeyObserverMock)
		assert     func(t *testing.T, err error, signer *jwtSigner)
	}{
		"without configuration": {
			assert: func(t *testing.T, err error, _ *jwtSigner) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "failed loading keystore")
			},
		},
		"no key id configured": {
			config: SignerConfig{
				Name:     "foo",
				KeyStore: KeyStore{Path: keyFile.Name()},
			},
			setupMocks: func(t *testing.T, wm *mocks.WatcherMock, kom *mocks2.KeyObserverMock) {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)
				kom.EXPECT().Notify(mock.Anything)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.NotNil(t, signer.signer)
				assert.Equal(t, keyFile.Name(), signer.path)
				assert.Empty(t, signer.keyID)
				assert.NotEmpty(t, signer.Hash())
			},
		},
		"with key id configured": {
			config: SignerConfig{
				Name:     "foo",
				KeyStore: KeyStore{Path: keyFile.Name()},
				KeyID:    "key2",
			},
			setupMocks: func(t *testing.T, wm *mocks.WatcherMock, kom *mocks2.KeyObserverMock) {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)
				kom.EXPECT().Notify(mock.Anything)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.NotNil(t, signer.signer)
				assert.Equal(t, keyFile.Name(), signer.path)
				assert.Equal(t, "key2", signer.keyID)
				assert.NotEmpty(t, signer.Hash())
			},
		},
		"with error while retrieving key from key store": {
			config: SignerConfig{
				Name:     "foo",
				KeyStore: KeyStore{Path: keyFile.Name()},
				KeyID:    "baz",
			},
			assert: func(t *testing.T, err error, _ *jwtSigner) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, keystore.ErrNoSuchKey)
			},
		},
		"with rsa 2048 key": {
			config: SignerConfig{
				Name:     "foo",
				KeyStore: KeyStore{Path: keyFile.Name()},
				KeyID:    "key1",
			},
			setupMocks: func(t *testing.T, wm *mocks.WatcherMock, kom *mocks2.KeyObserverMock) {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)
				kom.EXPECT().Notify(mock.Anything)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.NotNil(t, signer.signer)
				assert.Equal(t, keyFile.Name(), signer.path)
				assert.Equal(t, "key1", signer.keyID)
				assert.NotEmpty(t, signer.Hash())
			},
		},
		"with rsa 3072 key": {
			config: SignerConfig{
				Name:     "foo",
				KeyStore: KeyStore{Path: keyFile.Name()},
				KeyID:    "key2",
			},
			setupMocks: func(t *testing.T, wm *mocks.WatcherMock, kom *mocks2.KeyObserverMock) {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)
				kom.EXPECT().Notify(mock.Anything)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.NotNil(t, signer.signer)
				assert.Equal(t, keyFile.Name(), signer.path)
				assert.Equal(t, "key2", signer.keyID)
				assert.NotEmpty(t, signer.Hash())
			},
		},
		"with rsa 4096 key": {
			config: SignerConfig{
				Name:     "foo",
				KeyStore: KeyStore{Path: keyFile.Name()},
				KeyID:    "key3",
			},
			setupMocks: func(t *testing.T, wm *mocks.WatcherMock, kom *mocks2.KeyObserverMock) {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)
				kom.EXPECT().Notify(mock.Anything)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.NotNil(t, signer.signer)
				assert.Equal(t, keyFile.Name(), signer.path)
				assert.Equal(t, "key3", signer.keyID)
				assert.NotEmpty(t, signer.Hash())
			},
		},
		"with P256 ecdsa key": {
			config: SignerConfig{
				Name:     "foo",
				KeyStore: KeyStore{Path: keyFile.Name()},
				KeyID:    "key4",
			},
			setupMocks: func(t *testing.T, wm *mocks.WatcherMock, kom *mocks2.KeyObserverMock) {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)
				kom.EXPECT().Notify(mock.Anything)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.NotNil(t, signer.signer)
				assert.Equal(t, keyFile.Name(), signer.path)
				assert.Equal(t, "key4", signer.keyID)
				assert.NotEmpty(t, signer.Hash())
			},
		},
		"with P384 ecdsa key": {
			config: SignerConfig{
				Name:     "foo",
				KeyStore: KeyStore{Path: keyFile.Name()},
				KeyID:    "key5",
			},
			setupMocks: func(t *testing.T, wm *mocks.WatcherMock, kom *mocks2.KeyObserverMock) {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)
				kom.EXPECT().Notify(mock.Anything)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.NotNil(t, signer.signer)
				assert.Equal(t, keyFile.Name(), signer.path)
				assert.Equal(t, "key5", signer.keyID)
				assert.NotEmpty(t, signer.Hash())
			},
		},
		"with P512 ecdsa key": {
			config: SignerConfig{
				Name:     "foo",
				KeyStore: KeyStore{Path: keyFile.Name()},
				KeyID:    "key6",
			},
			setupMocks: func(t *testing.T, wm *mocks.WatcherMock, kom *mocks2.KeyObserverMock) {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)
				kom.EXPECT().Notify(mock.Anything)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.NotNil(t, signer.signer)
				assert.Equal(t, keyFile.Name(), signer.path)
				assert.Equal(t, "key6", signer.keyID)
				assert.NotEmpty(t, signer.Hash())
			},
		},
		"with not existing key store": {
			config: SignerConfig{
				Name:     "foo",
				KeyStore: KeyStore{Path: "/does/not/exist"},
			},
			assert: func(t *testing.T, err error, _ *jwtSigner) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed to get information about")
			},
		},
		"with certificate, which cannot be used for signature due to missing key usage": {
			config: SignerConfig{
				Name:     "foo",
				KeyStore: KeyStore{Path: keyFile.Name()},
				KeyID:    "missing_key_usage",
			},
			assert: func(t *testing.T, err error, _ *jwtSigner) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "missing key usage: DigitalSignature")
			},
		},
		"with self-signed certificate usable for JWT signing": {
			config: SignerConfig{
				Name:     "foo",
				KeyStore: KeyStore{Path: keyFile.Name()},
				KeyID:    "self_signed",
			},
			setupMocks: func(t *testing.T, wm *mocks.WatcherMock, kom *mocks2.KeyObserverMock) {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)
				kom.EXPECT().Notify(mock.Anything)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.NotNil(t, signer.signer)
				assert.Equal(t, keyFile.Name(), signer.path)
				assert.Equal(t, "self_signed", signer.keyID)
				assert.NotEmpty(t, signer.Hash())
			},
		},
		"with usable certificate including a full cert chain": {
			config: SignerConfig{
				Name:     "foo",
				KeyStore: KeyStore{Path: keyFile.Name()},
				KeyID:    "key7",
			},
			setupMocks: func(t *testing.T, wm *mocks.WatcherMock, kom *mocks2.KeyObserverMock) {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(nil)
				kom.EXPECT().Notify(mock.Anything)
			},
			assert: func(t *testing.T, err error, signer *jwtSigner) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foo", signer.iss)
				assert.NotNil(t, signer.signer)
				assert.Equal(t, keyFile.Name(), signer.path)
				assert.Equal(t, "key7", signer.keyID)
				assert.NotEmpty(t, signer.Hash())
			},
		},
		"fails due to error while registering with file watcher": {
			config: SignerConfig{
				Name:     "foo",
				KeyStore: KeyStore{Path: keyFile.Name()},
				KeyID:    "self_signed",
			},
			setupMocks: func(t *testing.T, wm *mocks.WatcherMock, kom *mocks2.KeyObserverMock) {
				t.Helper()

				wm.EXPECT().Add(mock.Anything, mock.Anything).Return(errors.New("test error"))
				kom.EXPECT().Notify(mock.Anything)
			},
			assert: func(t *testing.T, err error, _ *jwtSigner) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test error")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			ko := mocks2.NewKeyObserverMock(t)
			wm := mocks.NewWatcherMock(t)

			setupMocks := x.IfThenElse(
				tc.setupMocks != nil,
				tc.setupMocks,
				func(t *testing.T, _ *mocks.WatcherMock, _ *mocks2.KeyObserverMock) { t.Helper() },
			)

			setupMocks(t, wm, ko)

			// WHEN
			signer, err := newJWTSigner(&tc.config, wm, ko)

			// THEN
			tc.assert(t, err, signer)
		})
	}
}

func TestJWTSignerSign(t *testing.T) {
	t.Parallel()

	privKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKey := &privKey1.PublicKey

	subjectID := "foobar"
	ttl := 10 * time.Minute

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: privKey1},
		new(jose.SignerOptions).
			WithType("JWT").
			WithHeader("kid", "foo").
			WithHeader("alg", jose.ES256))
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		claims map[string]any
		assert func(t *testing.T, err error, rawJWT string, pubKey crypto.PublicKey, claims map[string]any)
	}{
		"sign claims which do not contain JWT specific claims": {
			claims: map[string]any{"baz": "zab", "bla": "foo"},
			assert: func(t *testing.T, err error, rawJWT string, pubKey crypto.PublicKey, claims map[string]any) {
				t.Helper()

				require.NoError(t, err)
				validateTestJWT(t, rawJWT, pubKey, "foo", subjectID, ttl, claims)
			},
		},
		"sign claims, which contain JWT specific claims": {
			claims: map[string]any{"iss": "bar"},
			assert: func(t *testing.T, err error, rawJWT string, pubKey crypto.PublicKey, claims map[string]any) {
				t.Helper()

				require.NoError(t, err)

				claims["iss"] = "foo"
				validateTestJWT(t, rawJWT, pubKey, "foo", subjectID, ttl, claims)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			signer := &jwtSigner{
				iss:    "foo",
				signer: sig,
			}

			// WHEN
			jwt, err := signer.Sign(subjectID, ttl, tc.claims)

			// THEN
			tc.assert(t, err, jwt, pubKey, tc.claims)
		})
	}
}

func validateTestJWT(
	t *testing.T,
	rawJWT string,
	pubKey crypto.PublicKey,
	expIss string,
	expSub string,
	ttl time.Duration,
	customClaims map[string]any,
) {
	t.Helper()

	var jwtClaims map[string]any

	require.Equal(t, 2, strings.Count(rawJWT, "."))

	token, err := jwt.ParseSigned(rawJWT, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)

	err = token.Claims(pubKey, &jwtClaims)
	require.NoError(t, err)

	assert.Contains(t, jwtClaims, "exp")
	assert.Contains(t, jwtClaims, "jti")
	assert.Contains(t, jwtClaims, "iat")
	assert.Contains(t, jwtClaims, "iss")
	assert.Contains(t, jwtClaims, "nbf")
	assert.Contains(t, jwtClaims, "sub")

	assert.Equal(t, expSub, jwtClaims["sub"])
	assert.Equal(t, expIss, jwtClaims["iss"])

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
			Organization: []string{"Test 2"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&privKey1.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSelfSigned(),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
		testsupport.WithSignaturePrivKey(privKey1)).
		Build()
	require.NoError(t, err)

	cert2, err := testsupport.NewCertificateBuilder(testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSerialNumber(big.NewInt(2)),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert 2",
			Organization: []string{"Test 2"},
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
		pemx.WithECDSAPrivateKey(privKey1, pemx.WithHeader("X-Key-ID", "key2")),
		pemx.WithX509Certificate(cert1),
	)
	require.NoError(t, err)

	pemFile, err := os.Create(filepath.Join(testDir, "keystore.pem"))
	require.NoError(t, err)

	_, err = pemFile.Write(pemBytes1)
	require.NoError(t, err)

	ko := mocks2.NewKeyObserverMock(t)
	ko.EXPECT().Notify(mock.Anything).
		Run(mock2.NewArgumentCaptor[keyregistry.KeyInfo](&ko.Mock, "captor").Capture).
		Times(3)

	signer := &jwtSigner{path: pemFile.Name(), keyID: "key1", ko: ko}
	err = signer.load()
	require.NoError(t, err)

	// WHEN
	_, err = pemFile.Seek(0, 0)
	require.NoError(t, err)

	_, err = pemFile.Write(pemBytes2)
	require.NoError(t, err)

	signer.OnChanged(log.Logger)

	// WHEN
	err = os.Truncate(pemFile.Name(), 0)
	require.NoError(t, err)

	signer.OnChanged(log.Logger)

	// THEN
	keyInfos := mock2.ArgumentCaptorFrom[keyregistry.KeyInfo](&ko.Mock, "captor").Values()
	require.Len(t, keyInfos, 3)

	assert.True(t, keyInfos[0].Exportable)
	assert.Equal(t, "key1", keyInfos[0].KeyID)
	assert.Equal(t, cert1, keyInfos[0].CertChain[0])

	assert.True(t, keyInfos[1].Exportable)
	assert.Equal(t, "key1", keyInfos[1].KeyID)
	assert.Equal(t, cert2, keyInfos[1].CertChain[0])

	assert.True(t, keyInfos[2].Exportable)
	assert.Equal(t, "key2", keyInfos[2].KeyID)
	assert.Equal(t, cert1, keyInfos[2].CertChain[0])
}
