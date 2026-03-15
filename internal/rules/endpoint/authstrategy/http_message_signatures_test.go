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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dadrus/httpsig"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/keyregistry"
	"github.com/dadrus/heimdall/internal/keyregistry/mocks"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
	mock2 "github.com/dadrus/heimdall/internal/x/testsupport/mock"
)

func TestToHTTPSigKey(t *testing.T) {
	t.Parallel()

	for alg, kse := range map[httpsig.SignatureAlgorithm]*keystore.Entry{
		httpsig.RsaPssSha256:    {KeyID: "foo", Alg: keystore.AlgRSA, KeySize: 2048, PrivateKey: &rsa.PrivateKey{}},
		httpsig.RsaPssSha384:    {KeyID: "foo", Alg: keystore.AlgRSA, KeySize: 3072, PrivateKey: &rsa.PrivateKey{}},
		httpsig.RsaPssSha512:    {KeyID: "foo", Alg: keystore.AlgRSA, KeySize: 4096, PrivateKey: &rsa.PrivateKey{}},
		httpsig.EcdsaP256Sha256: {KeyID: "foo", Alg: keystore.AlgECDSA, KeySize: 256, PrivateKey: &ecdsa.PrivateKey{}},
		httpsig.EcdsaP384Sha384: {KeyID: "foo", Alg: keystore.AlgECDSA, KeySize: 384, PrivateKey: &ecdsa.PrivateKey{}},
		httpsig.EcdsaP521Sha512: {KeyID: "foo", Alg: keystore.AlgECDSA, KeySize: 512, PrivateKey: &ecdsa.PrivateKey{}},
	} {
		t.Run(string(alg), func(t *testing.T) {
			key := toHTTPSigKey(kse)

			assert.Equal(t, alg, key.Algorithm)
			assert.Equal(t, kse.KeyID, key.KeyID)
			assert.Equal(t, kse.PrivateKey, key.Key)
		})
	}
}

func TestHTTPMessageSignaturesInit(t *testing.T) {
	t.Parallel()

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
	ee1cert, err := intCA.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&ee1PrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
	require.NoError(t, err)

	ee2PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	ee2cert, err := intCA.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 2",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&ee2PrivKey.PublicKey, x509.ECDSAWithSHA384))
	require.NoError(t, err)

	pemBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(ee1PrivKey, pemx.WithHeader("X-Key-ID", "key1")),
		pemx.WithX509Certificate(ee1cert),
		pemx.WithECDSAPrivateKey(ee2PrivKey, pemx.WithHeader("X-Key-ID", "key2")),
		pemx.WithX509Certificate(ee2cert),
		pemx.WithX509Certificate(intCACert),
		pemx.WithX509Certificate(rootCA.Certificate),
	)
	require.NoError(t, err)

	testDir := t.TempDir()
	trustStorePath := filepath.Join(testDir, "keystore.pem")

	err = os.WriteFile(trustStorePath, pemBytes, 0o600)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		conf      *HTTPMessageSignatures
		setupMock func(t *testing.T, ko *mocks.KeyObserverMock)
		assert    func(t *testing.T, err error, conf *HTTPMessageSignatures)
	}{
		"failed loading keystore": {
			conf: &HTTPMessageSignatures{},
			assert: func(t *testing.T, err error, _ *HTTPMessageSignatures) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed loading keystore")
			},
		},
		"no key for given key id": {
			conf: &HTTPMessageSignatures{
				Signer: SignerConfig{KeyStore: KeyStore{Path: trustStorePath}, KeyID: "foo"},
			},
			assert: func(t *testing.T, err error, _ *HTTPMessageSignatures) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed retrieving key from key store")
			},
		},
		"certificate cannot be used for signing": {
			conf: &HTTPMessageSignatures{
				Signer: SignerConfig{KeyStore: KeyStore{Path: trustStorePath}, KeyID: "key2"},
			},
			assert: func(t *testing.T, err error, _ *HTTPMessageSignatures) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "cannot be used for signing purposes")
			},
		},
		"bad signer configuration": {
			conf: &HTTPMessageSignatures{
				Signer:     SignerConfig{KeyStore: KeyStore{Path: trustStorePath}},
				Components: []string{"@foo"},
			},
			assert: func(t *testing.T, err error, _ *HTTPMessageSignatures) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed to configure")
			},
		},
		"successful configuration with default ttl": {
			conf: &HTTPMessageSignatures{
				Signer:     SignerConfig{KeyStore: KeyStore{Path: trustStorePath}, KeyID: "key1"},
				Components: []string{"@method"},
			},
			setupMock: func(t *testing.T, ko *mocks.KeyObserverMock) {
				t.Helper()

				ko.EXPECT().Notify(mock.Anything)
			},
			assert: func(t *testing.T, err error, conf *HTTPMessageSignatures) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, conf.signer)
			},
		},
		"successful configuration with custom ttl": {
			conf: &HTTPMessageSignatures{
				Signer:     SignerConfig{KeyStore: KeyStore{Path: trustStorePath}, KeyID: "key1"},
				Components: []string{"@method"},
				TTL:        new(1 * time.Hour),
			},
			setupMock: func(t *testing.T, ko *mocks.KeyObserverMock) {
				t.Helper()

				ko.EXPECT().Notify(mock.Anything)
			},
			assert: func(t *testing.T, err error, conf *HTTPMessageSignatures) {
				t.Helper()

				require.NoError(t, err)

				assert.NotNil(t, conf.signer)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			kr := mocks.NewKeyObserverMock(t)
			tc.conf.co = kr

			setupMock := x.IfThenElse(
				tc.setupMock != nil,
				tc.setupMock,
				func(t *testing.T, _ *mocks.KeyObserverMock) { t.Helper() },
			)
			setupMock(t, kr)

			err := tc.conf.init()

			tc.assert(t, err, tc.conf)
		})
	}
}

func TestHTTPMessageSignaturesHash(t *testing.T) {
	t.Parallel()

	ttl := 1 * time.Hour
	conf1 := &HTTPMessageSignatures{
		Signer:     SignerConfig{KeyStore: KeyStore{Path: "/path/to/keystore.pem"}, KeyID: "key1"},
		Components: []string{"@method"},
		TTL:        &ttl,
	}
	conf2 := &HTTPMessageSignatures{
		Signer:     SignerConfig{KeyStore: KeyStore{Path: "/path/to/keystore.pem"}, KeyID: "key1", Name: "foo"},
		Components: []string{"@status"},
		TTL:        &ttl,
		Label:      "test",
	}

	hash1 := conf1.Hash()
	hash2 := conf2.Hash()

	assert.NotEmpty(t, hash1)
	assert.NotEmpty(t, hash2)
	assert.NotEqual(t, hash1, hash2)
	assert.Equal(t, hash1, conf1.Hash())
	assert.Equal(t, hash2, conf2.Hash())
}

func TestHTTPMessageSignaturesApply(t *testing.T) {
	t.Parallel()

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cb := testsupport.NewCertificateBuilder(
		testsupport.WithValidity(time.Now(), 15*time.Second),
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&privKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSelfSigned(),
		testsupport.WithSignaturePrivKey(privKey),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
	)

	cert, err := cb.Build()
	require.NoError(t, err)

	pemBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(privKey, pemx.WithHeader("X-Key-ID", "test")),
		pemx.WithX509Certificate(cert),
	)
	require.NoError(t, err)

	testDir := t.TempDir()
	trustStorePath := filepath.Join(testDir, "keystore.pem")

	err = os.WriteFile(trustStorePath, pemBytes, 0o600)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		conf   *HTTPMessageSignatures
		assert func(t *testing.T, err error, req *http.Request)
	}{
		"fails": {
			conf: &HTTPMessageSignatures{
				Signer:     SignerConfig{KeyStore: KeyStore{Path: trustStorePath}},
				Components: []string{"x-some-header"},
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "x-some-header")
				assert.Empty(t, req.Header.Get("Signature"))
				assert.Empty(t, req.Header.Get("Signature-Input"))
			},
		},
		"successful": {
			conf: &HTTPMessageSignatures{
				Signer:     SignerConfig{KeyStore: KeyStore{Path: trustStorePath}},
				Components: []string{"@method", "content-digest"},
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEmpty(t, req.Header.Get("Signature"))
				sigInput := req.Header.Get("Signature-Input")
				assert.Contains(t, sigInput, `("@method" "content-digest")`)
				assert.Contains(t, sigInput, `created=`)
				assert.Contains(t, sigInput, `expires=`)
				assert.Contains(t, sigInput, `keyid="test"`)
				assert.Contains(t, sigInput, `alg="ecdsa-p384-sha384"`)
				assert.Contains(t, sigInput, `nonce=`)
				assert.Contains(t, sigInput, `tag="heimdall"`)

				contentDigest := req.Header.Get("Content-Digest")
				assert.Contains(t, contentDigest, "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:")
				assert.Contains(t, contentDigest, "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			kr := mocks.NewKeyObserverMock(t)
			kr.EXPECT().Notify(mock.Anything)

			tc.conf.co = kr

			err := tc.conf.init()
			require.NoError(t, err)

			req, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"http//example.com/test",
				strings.NewReader(`{"hello": "world"}`),
			)
			require.NoError(t, err)

			err = tc.conf.Apply(t.Context(), req)

			tc.assert(t, err, req)
		})
	}
}

func TestHTTPMessageSignaturesOnChanged(t *testing.T) {
	t.Parallel()

	// GIVEN
	testDir := t.TempDir()

	privKey1, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	privKey2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cert1, err := testsupport.NewCertificateBuilder(
		testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert 1",
			Organization: []string{"Test 1"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&privKey1.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSelfSigned(),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
		testsupport.WithSignaturePrivKey(privKey1)).
		Build()
	require.NoError(t, err)

	cert2, err := testsupport.NewCertificateBuilder(
		testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSerialNumber(big.NewInt(1)),
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

	ko := mocks.NewKeyObserverMock(t)
	ko.EXPECT().Notify(mock.Anything).
		Run(mock2.NewArgumentCaptor[keyregistry.KeyInfo](&ko.Mock, "captor1").Capture).
		Times(3)

	conf := &HTTPMessageSignatures{
		Signer:     SignerConfig{KeyStore: KeyStore{Path: pemFile.Name()}, KeyID: "key1"},
		Components: []string{"@method"},
		co:         ko,
	}
	err = conf.init()
	require.NoError(t, err)

	// WHEN
	_, err = pemFile.Seek(0, 0)
	require.NoError(t, err)

	_, err = pemFile.Write(pemBytes2)
	require.NoError(t, err)

	conf.OnChanged(log.Logger)

	// WHEN
	err = os.Truncate(pemFile.Name(), 0)
	require.NoError(t, err)

	conf.OnChanged(log.Logger)

	// THEN
	keyInfos := mock2.ArgumentCaptorFrom[keyregistry.KeyInfo](&ko.Mock, "captor1").Values()
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
