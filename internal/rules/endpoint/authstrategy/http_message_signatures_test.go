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
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestToHTTPSigKey(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		kse    *keystore.Entry
		expAlg httpsig.SignatureAlgorithm
	}{
		{
			expAlg: httpsig.RsaPssSha256,
			kse:    &keystore.Entry{KeyID: "foo", Alg: keystore.AlgRSA, KeySize: 2048, PrivateKey: &rsa.PrivateKey{}},
		},
		{
			expAlg: httpsig.RsaPssSha384,
			kse:    &keystore.Entry{KeyID: "foo", Alg: keystore.AlgRSA, KeySize: 3072, PrivateKey: &rsa.PrivateKey{}},
		},
		{
			expAlg: httpsig.RsaPssSha512,
			kse:    &keystore.Entry{KeyID: "foo", Alg: keystore.AlgRSA, KeySize: 4096, PrivateKey: &rsa.PrivateKey{}},
		},
		{
			expAlg: httpsig.EcdsaP256Sha256,
			kse:    &keystore.Entry{KeyID: "foo", Alg: keystore.AlgECDSA, KeySize: 256, PrivateKey: &ecdsa.PrivateKey{}},
		},
		{
			expAlg: httpsig.EcdsaP384Sha384,
			kse:    &keystore.Entry{KeyID: "foo", Alg: keystore.AlgECDSA, KeySize: 384, PrivateKey: &ecdsa.PrivateKey{}},
		},
		{
			expAlg: httpsig.EcdsaP521Sha512,
			kse:    &keystore.Entry{KeyID: "foo", Alg: keystore.AlgECDSA, KeySize: 512, PrivateKey: &ecdsa.PrivateKey{}},
		},
	} {
		t.Run(string(tc.expAlg), func(t *testing.T) {
			key := toHTTPSigKey(tc.kse)

			assert.Equal(t, tc.expAlg, key.Algorithm)
			assert.Equal(t, tc.kse.KeyID, key.KeyID)
			assert.Equal(t, tc.kse.PrivateKey, key.Key)
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

	for _, tc := range []struct {
		uc     string
		conf   *HTTPMessageSignatures
		assert func(t *testing.T, err error, conf *HTTPMessageSignatures)
	}{
		{
			uc:   "failed loading keystore",
			conf: &HTTPMessageSignatures{},
			assert: func(t *testing.T, err error, _ *HTTPMessageSignatures) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed loading keystore")
			},
		},
		{
			uc: "no key for given key id",
			conf: &HTTPMessageSignatures{
				Signer: SignerConfig{KeyStore: KeyStore{Path: trustStorePath}, KeyID: "foo"},
			},
			assert: func(t *testing.T, err error, _ *HTTPMessageSignatures) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed retrieving key from key store")
			},
		},
		{
			uc: "certificate cannot be used for signing",
			conf: &HTTPMessageSignatures{
				Signer: SignerConfig{KeyStore: KeyStore{Path: trustStorePath}, KeyID: "key2"},
			},
			assert: func(t *testing.T, err error, _ *HTTPMessageSignatures) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "cannot be used for signing purposes")
			},
		},
		{
			uc: "bad signer configuration",
			conf: &HTTPMessageSignatures{
				Signer:     SignerConfig{KeyStore: KeyStore{Path: trustStorePath}},
				Components: []string{"@foo"},
			},
			assert: func(t *testing.T, err error, _ *HTTPMessageSignatures) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed to configure")
			},
		},
		{
			uc: "successful configuration with default ttl",
			conf: &HTTPMessageSignatures{
				Signer:     SignerConfig{KeyStore: KeyStore{Path: trustStorePath}, KeyID: "key1"},
				Components: []string{"@method"},
			},
			assert: func(t *testing.T, err error, conf *HTTPMessageSignatures) {
				t.Helper()

				require.NoError(t, err)

				assert.NotNil(t, conf.signer)
				assert.NotEmpty(t, conf.Certificates())
				assert.NotEmpty(t, conf.Keys())
				assert.Equal(t, "http message signer", conf.Name())
			},
		},
		{
			uc: "successful configuration with custom ttl",
			conf: &HTTPMessageSignatures{
				Signer:     SignerConfig{KeyStore: KeyStore{Path: trustStorePath}, KeyID: "key1"},
				Components: []string{"@method"},
				TTL: func() *time.Duration {
					ttl := 1 * time.Hour

					return &ttl
				}(),
			},
			assert: func(t *testing.T, err error, conf *HTTPMessageSignatures) {
				t.Helper()

				require.NoError(t, err)

				assert.NotNil(t, conf.signer)
				assert.NotEmpty(t, conf.Certificates())
				assert.NotEmpty(t, conf.Keys())
				assert.Equal(t, "http message signer", conf.Name())
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
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

	for _, tc := range []struct {
		uc     string
		conf   *HTTPMessageSignatures
		assert func(t *testing.T, err error, req *http.Request)
	}{
		{
			uc: "fails",
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
		{
			uc: "successful",
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
		t.Run(tc.uc, func(t *testing.T) {
			err := tc.conf.init()
			require.NoError(t, err)

			req, err := http.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				"http//example.com/test",
				strings.NewReader(`{"hello": "world"}`),
			)
			require.NoError(t, err)

			err = tc.conf.Apply(context.Background(), req)

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

	conf := &HTTPMessageSignatures{
		Signer:     SignerConfig{KeyStore: KeyStore{Path: pemFile.Name()}, KeyID: "key1"},
		Components: []string{"@method"},
	}
	err = conf.init()
	require.NoError(t, err)

	require.Equal(t, cert1, conf.certChain[0])
	require.Equal(t, &privKey1.PublicKey, conf.pubKeys[0].Key)

	// WHEN
	_, err = pemFile.Seek(0, 0)
	require.NoError(t, err)

	_, err = pemFile.Write(pemBytes2)
	require.NoError(t, err)

	conf.OnChanged(log.Logger)

	// THEN
	require.Equal(t, cert2, conf.certChain[0])
	require.Equal(t, &privKey2.PublicKey, conf.pubKeys[0].Key)

	// WHEN
	err = os.Truncate(pemFile.Name(), 0)
	require.NoError(t, err)

	conf.OnChanged(log.Logger)

	// THEN
	require.Equal(t, cert2, conf.certChain[0])
	require.Equal(t, &privKey2.PublicKey, conf.pubKeys[0].Key)
}
