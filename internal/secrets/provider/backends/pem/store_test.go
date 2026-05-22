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
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	x509pkix "crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/x/pkix"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewKeyStoreFromPEMFile(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		pemFile func(*testing.T) string
		assert  func(*testing.T, keyStore, error)
	}{
		"returns configuration error if file does not exist": {
			pemFile: func(t *testing.T) string {
				t.Helper()

				return filepath.Join(t.TempDir(), "missing.pem")
			},
			assert: func(t *testing.T, _ keyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
			},
		},
		"returns configuration error if path points to directory": {
			pemFile: func(t *testing.T) string {
				t.Helper()

				return t.TempDir()
			},
			assert: func(t *testing.T, _ keyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "is not a file")
			},
		},
		"returns configuration error if file cannot be read": {
			pemFile: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "unreadable.pem")
				err := os.WriteFile(path, []byte("invalid"), 0o600)
				require.NoError(t, err)
				require.NoError(t, os.Chmod(path, 0o000))

				return path
			},
			assert: func(t *testing.T, _ keyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "failed to read")
			},
		},
		"returns configuration error if pem has no key material": {
			pemFile: func(t *testing.T) string {
				t.Helper()

				ca, err := testsupport.NewRootCA("PEM Test CA", 24*time.Hour)
				require.NoError(t, err)

				pemBytes, err := pemx.BuildPEM(pemx.WithX509Certificate(ca.Certificate))
				require.NoError(t, err)

				path := filepath.Join(t.TempDir(), "cert-only.pem")
				err = os.WriteFile(path, pemBytes, 0o600)
				require.NoError(t, err)

				return path
			},
			assert: func(t *testing.T, _ keyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "no key material present")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			ks, err := newKeyStoreFromPEMFile(tc.pemFile(t), "")
			tc.assert(t, ks, err)
		})
	}
}

func TestNewKeyStoreFromPEMBytes(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		password string
		pemBytes func(*testing.T) []byte
		assert   func(*testing.T, keyStore, error)
	}{
		"supports encrypted pkcs8 keys": {
			password: "password",
			pemBytes: func(t *testing.T) []byte {
				t.Helper()

				return []byte(pemPKCS8ECEncryptedPrivateKey)
			},
			assert: func(t *testing.T, ks keyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, ks, 1)
				secret, ok := ks[0].(provider.AsymmetricKeySecret)
				require.True(t, ok)
				assert.IsType(t, &ecdsa.PrivateKey{}, secret.PrivateKey())
			},
		},
		"supports mixed rsa and ecdsa keys": {
			password: "password",
			pemBytes: func(t *testing.T) []byte {
				t.Helper()

				ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)

				rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				pemBytes, err := pemx.BuildPEM(
					pemx.WithECDSAPrivateKey(ecKey),
					pemx.WithRSAPrivateKey(rsaKey),
				)
				require.NoError(t, err)

				return pemBytes
			},
			assert: func(t *testing.T, ks keyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, ks, 2)

				assert.IsType(t, &ecdsa.PrivateKey{}, secretAt(t, ks, 0).PrivateKey())
				assert.IsType(t, &rsa.PrivateKey{}, secretAt(t, ks, 1).PrivateKey())
				assert.NotEqual(t, secretAt(t, ks, 0).KeyID(), secretAt(t, ks, 1).KeyID())
			},
		},
		"returns internal error for pkcs8 key without signer support": {
			pemBytes: func(t *testing.T) []byte {
				t.Helper()

				key, err := ecdh.X25519().GenerateKey(rand.Reader)
				require.NoError(t, err)

				der, err := x509.MarshalPKCS8PrivateKey(key)
				require.NoError(t, err)

				return pem.EncodeToMemory(&pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: der,
				})
			},
			assert: func(t *testing.T, _ keyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrInternal)
				require.ErrorContains(t, err, "does not implement crypto.Signer")
			},
		},
		"returns configuration error for duplicate ec key across pem formats": {
			password: "password",
			pemBytes: func(t *testing.T) []byte {
				t.Helper()

				buf := bytes.NewBufferString(pemPKCS1ECPrivateKey)
				_, err := buf.WriteString(pemPKCS8ECEncryptedPrivateKey)
				require.NoError(t, err)
				_, err = buf.WriteString(pemPKCS8ECPrivateKey)
				require.NoError(t, err)

				return buf.Bytes()
			},
			assert: func(t *testing.T, _ keyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "duplicate entry")
			},
		},
		"returns configuration error for duplicate rsa key across pem formats": {
			pemBytes: func(t *testing.T) []byte {
				t.Helper()

				buf := bytes.NewBufferString(pemPKCS1RSAPrivateKey)
				_, err := buf.WriteString(pemPKCS8RSAPrivateKey)
				require.NoError(t, err)

				return buf.Bytes()
			},
			assert: func(t *testing.T, _ keyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "duplicate entry")
			},
		},
		"returns internal error for unsupported pem block type": {
			pemBytes: func(t *testing.T) []byte {
				t.Helper()

				return []byte(`
-----BEGIN FOOBAR KEY-----
MHcCAQEEIAcCM9VY6RRiUlz3UoywbT9yN9UlWEEWKIPqiA2D86pCoAoGCCqGSM49
AwEHoUQDQgAEPEmirqVF2KoNguFuh4GGyShM3OIZt/yD6WESlOvAJhJX6HZyOgFu
xijD/4gPFRBfs2GsfVZzSL9kH7HH0chB9w==
-----END FOOBAR KEY-----
`)
			},
			assert: func(t *testing.T, _ keyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrInternal)
				require.ErrorContains(t, err, "unsupported entry")
			},
		},
		"returns internal error for malformed key data": {
			pemBytes: func(t *testing.T) []byte {
				t.Helper()

				return []byte(`
-----BEGIN RSA PRIVATE KEY-----
MHcCAQEEIAcCM9VY6RRiUlz3UoywbT9yN9UlWEEWKIPqiA2D86pCoAoGCCqGSM49
AwEHoUQDQgAEPEmirqVF2KoNguFuh4GGyShM3OIZt/yD6WESlOvAJhJX6HZyOgFu
xijD/4gPFRBfs2GsfVZzSL9kH7HH0chB9w==
-----END RSA PRIVATE KEY-----
`)
			},
			assert: func(t *testing.T, _ keyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrInternal)
				require.ErrorContains(t, err, "failed to parse")
			},
		},
		"returns configuration error for duplicate key id": {
			pemBytes: func(t *testing.T) []byte {
				t.Helper()

				key1, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				key2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)

				pemBytes, err := pemx.BuildPEM(
					pemx.WithECDSAPrivateKey(key1, pemx.WithHeader("X-Key-ID", "dup")),
					pemx.WithECDSAPrivateKey(key2, pemx.WithHeader("X-Key-ID", "dup")),
				)
				require.NoError(t, err)

				return pemBytes
			},
			assert: func(t *testing.T, _ keyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "duplicate entry for key id=dup")
			},
		},
		"generates key id from cert subject key id if present": {
			pemBytes: func(t *testing.T) []byte {
				t.Helper()

				key, cert, ca := createLeafAndCA(t, []byte("kid-by-cert"))

				pemBytes, err := pemx.BuildPEM(
					pemx.WithECDSAPrivateKey(key),
					pemx.WithX509Certificate(cert),
					pemx.WithX509Certificate(ca.Certificate),
				)
				require.NoError(t, err)

				return pemBytes
			},
			assert: func(t *testing.T, ks keyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, ks, 1)
				secret, ok := ks[0].(provider.AsymmetricKeySecret)
				require.True(t, ok)
				assert.Equal(t, hex.EncodeToString(secret.CertChain()[0].SubjectKeyId), secret.KeyID())
				assert.Len(t, secret.CertChain(), 2)
			},
		},
		"generates key id from public key if cert subject key id missing": {
			pemBytes: func(t *testing.T) []byte {
				t.Helper()

				key, cert, ca := createLeafAndCA(t, nil)

				pemBytes, err := pemx.BuildPEM(
					pemx.WithECDSAPrivateKey(key),
					pemx.WithX509Certificate(cert),
					pemx.WithX509Certificate(ca.Certificate),
				)
				require.NoError(t, err)

				return pemBytes
			},
			assert: func(t *testing.T, ks keyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, ks, 1)
				secret, ok := ks[0].(provider.AsymmetricKeySecret)
				require.True(t, ok)

				expectedKid, err := pkix.SubjectKeyID(secret.PrivateKey().Public())
				require.NoError(t, err)
				assert.Equal(t, hex.EncodeToString(expectedKid), secret.KeyID())
			},
		},
		"keeps explicit X-Key-ID over generated key id": {
			pemBytes: func(t *testing.T) []byte {
				t.Helper()

				key, cert, ca := createLeafAndCA(t, []byte("kid-by-cert"))

				pemBytes, err := pemx.BuildPEM(
					pemx.WithECDSAPrivateKey(key, pemx.WithHeader("X-Key-ID", "custom-kid")),
					pemx.WithX509Certificate(cert),
					pemx.WithX509Certificate(ca.Certificate),
				)
				require.NoError(t, err)

				return pemBytes
			},
			assert: func(t *testing.T, ks keyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, ks, 1)
				secret, ok := ks[0].(provider.AsymmetricKeySecret)
				require.True(t, ok)
				assert.Equal(t, "custom-kid", secret.KeyID())
				assert.Equal(t, ks[0].Selector(), secret.KeyID())
			},
		},
		"keeps explicit X-Key-ID without certificates": {
			pemBytes: func(t *testing.T) []byte {
				t.Helper()

				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)

				pemBytes, err := pemx.BuildPEM(
					pemx.WithECDSAPrivateKey(key, pemx.WithHeader("X-Key-ID", "explicit-kid")),
				)
				require.NoError(t, err)

				return pemBytes
			},
			assert: func(t *testing.T, ks keyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, ks, 1)
				secret := secretAt(t, ks, 0)
				assert.Equal(t, "explicit-kid", secret.KeyID())
				assert.Equal(t, "explicit-kid", secret.Selector())
				assert.Empty(t, secret.CertChain())
			},
		},
		"returns configuration error for invalid certificate chain": {
			pemBytes: func(t *testing.T) []byte {
				t.Helper()

				privateKey, leafCert, malformedIntermediate := createLeafWithMalformedIntermediateCA(t)

				pemBytes, err := pemx.BuildPEM(
					pemx.WithECDSAPrivateKey(privateKey),
					pemx.WithX509Certificate(leafCert),
					pemx.WithX509Certificate(malformedIntermediate),
				)
				require.NoError(t, err)

				return pemBytes
			},
			assert: func(t *testing.T, _ keyStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "invalid certificate chain")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			ks, err := newKeyStoreFromPEMBytes(tc.pemBytes(t), tc.password)
			tc.assert(t, ks, err)
		})
	}
}

func TestFindChain(t *testing.T) {
	t.Parallel()

	rootCA, intermediateCA, leafCert, privateKey := createLeafWithIntermediateCA(t)

	for uc, tc := range map[string]struct {
		pool   []*x509.Certificate
		key    crypto.PublicKey
		assert func(*testing.T, []*x509.Certificate)
	}{
		"returns full chain": {
			pool: []*x509.Certificate{
				leafCert,
				intermediateCA.Certificate,
				rootCA.Certificate,
			},
			key: privateKey.Public(),
			assert: func(t *testing.T, chain []*x509.Certificate) {
				t.Helper()

				require.Len(t, chain, 3)
				assert.True(t, chain[0].Equal(leafCert))
				assert.True(t, chain[1].Equal(intermediateCA.Certificate))
				assert.True(t, chain[2].Equal(rootCA.Certificate))
			},
		},
		"returns only the leaf certificate if intermediate is missing": {
			pool: []*x509.Certificate{
				leafCert,
				rootCA.Certificate,
			},
			key: privateKey.Public(),
			assert: func(t *testing.T, chain []*x509.Certificate) {
				t.Helper()

				require.Len(t, chain, 1)
				assert.True(t, chain[0].Equal(leafCert))
			},
		},
		"returns nil if no matching certificate exists": {
			pool: []*x509.Certificate{
				rootCA.Certificate,
				intermediateCA.Certificate,
			},
			key: privateKey.Public(),
			assert: func(t *testing.T, chain []*x509.Certificate) {
				t.Helper()

				assert.Nil(t, chain)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, findChain(tc.key, tc.pool))
		})
	}
}

func TestValidateChain(t *testing.T) {
	t.Parallel()

	rootCA, intermediateCA, leafCert, _ := createLeafWithIntermediateCA(t)
	badRootCA, err := testsupport.NewRootCA("PEM Bad Root CA", 24*time.Hour)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		chain  []*x509.Certificate
		assert func(*testing.T, error)
	}{
		"accepts valid chain": {
			chain: []*x509.Certificate{
				leafCert,
				intermediateCA.Certificate,
				rootCA.Certificate,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"returns configuration error for incomplete chain": {
			chain: []*x509.Certificate{
				leafCert,
				rootCA.Certificate,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "invalid certificate chain")
			},
		},
		"returns configuration error for malformed issuer": {
			chain: []*x509.Certificate{
				leafCert,
				intermediateCA.Certificate,
				badRootCA.Certificate,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "invalid certificate chain")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, validateChain(tc.chain))
		})
	}
}

func TestNewKeyStoreFromKey(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ks, err := newKeyStoreFromKey("test", key)
	require.NoError(t, err)
	require.Len(t, ks, 1)

	secret, ok := ks[0].(provider.AsymmetricKeySecret)
	require.True(t, ok)

	assert.Equal(t, provider.SecretKindAsymmetricKey, secret.Kind())
	assert.IsType(t, &rsa.PrivateKey{}, secret.PrivateKey())
	assert.NotEmpty(t, secret.KeyID())
	assert.Equal(t, secret.Selector(), secret.KeyID())
}

func TestKeyStoreGet(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pemBytes, err := pemx.BuildPEM(pemx.WithRSAPrivateKey(key, pemx.WithHeader("X-Key-ID", "first")))
	require.NoError(t, err)

	ks, err := newKeyStoreFromPEMBytes(pemBytes, "")
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		keyID  string
		assert func(*testing.T, error)
	}{
		"returns entry for existing key": {
			keyID: "first",
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
		"returns error for missing key": {
			keyID: "missing",
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrSecretNotFound)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			_, err := ks.get(tc.keyID)
			tc.assert(t, err)
		})
	}
}

func createLeafAndCA(t *testing.T, subjectKeyID []byte) (*ecdsa.PrivateKey, *x509.Certificate, *testsupport.CA) {
	t.Helper()

	ca, err := testsupport.NewRootCA("PEM Test CA", 24*time.Hour)
	require.NoError(t, err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	opts := []testsupport.CertificateBuilderOption{
		testsupport.WithSubject(x509pkix.Name{
			CommonName:   "PEM Test EE",
			Organization: []string{"Heimdall"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour),
		testsupport.WithSubjectPubKey(&privateKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
	}
	if subjectKeyID != nil {
		opts = append(opts, testsupport.WithSubjectKeyID(subjectKeyID))
	}

	cert, err := ca.IssueCertificate(opts...)
	require.NoError(t, err)

	return privateKey, cert, ca
}

func createLeafWithIntermediateCA(
	t *testing.T,
) (*testsupport.CA, *testsupport.CA, *x509.Certificate, *ecdsa.PrivateKey) {
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

	return rootCA, intermediateCA, leafCert, privateKey
}

func createLeafWithMalformedIntermediateCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate) {
	t.Helper()

	rootCA, err := testsupport.NewRootCA("PEM Test Root CA", 24*time.Hour)
	require.NoError(t, err)

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	malformedIntermediate, err := rootCA.IssueCertificate(
		testsupport.WithSubject(x509pkix.Name{
			CommonName:   "PEM Malformed Intermediate",
			Organization: []string{"Heimdall"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour),
		testsupport.WithSubjectPubKey(&intermediateKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithGeneratedSubjectKeyID(),
	)
	require.NoError(t, err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	leafCert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          bigOne(t),
		Subject:               x509pkix.Name{CommonName: "PEM Test EE", Organization: []string{"Heimdall"}, Country: []string{"EU"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		AuthorityKeyId:        malformedIntermediate.SubjectKeyId,
		RawIssuer:             malformedIntermediate.RawSubject,
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
	}, malformedIntermediate, &privateKey.PublicKey, intermediateKey)
	require.NoError(t, err)

	parsedLeafCert, err := x509.ParseCertificate(leafCert)
	require.NoError(t, err)

	return privateKey, parsedLeafCert, malformedIntermediate
}

func bigOne(t *testing.T) *big.Int {
	t.Helper()

	return big.NewInt(1)
}

func secretAt(t *testing.T, ks keyStore, idx int) provider.AsymmetricKeySecret {
	t.Helper()

	secret, ok := ks[idx].(provider.AsymmetricKeySecret)
	require.True(t, ok)

	return secret
}

const pemPKCS8ECEncryptedPrivateKey = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAiJ8VMMyD9LkQICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEDM4MvufeWaeKFIyuILKBAYEgZC0
iSSw1qwqVWxIik/YWxn90MvvNCg9P1MHyF2i5w7Xp+uPFjRM4o+7PdHhRgJSnsDT
6JYTU6S5Gdl6t5JsFqhIBDYyqrs/+cegw0dSGl/B/UoZ0taNK66RKQ6wuv/VCcuY
MtusvyePIsJKGGKsTyHwla4eWpjorL+V116zP35J5x32AFIT8hCbZlLGdL5dpVU=
-----END ENCRYPTED PRIVATE KEY-----
`

//nolint:gosec
const pemPKCS1ECPrivateKey = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAcCM9VY6RRiUlz3UoywbT9yN9UlWEEWKIPqiA2D86pCoAoGCCqGSM49
AwEHoUQDQgAEPEmirqVF2KoNguFuh4GGyShM3OIZt/yD6WESlOvAJhJX6HZyOgFu
xijD/4gPFRBfs2GsfVZzSL9kH7HH0chB9w==
-----END EC PRIVATE KEY-----
`

const pemPKCS8ECPrivateKey = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBwIz1VjpFGJSXPdS
jLBtP3I31SVYQRYog+qIDYPzqkKhRANCAAQ8SaKupUXYqg2C4W6HgYbJKEzc4hm3
/IPpYRKU68AmElfodnI6AW7GKMP/iA8VEF+zYax9VnNIv2QfscfRyEH3
-----END PRIVATE KEY-----
`

//nolint:gosec
const pemPKCS1RSAPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvxc3ZHNNVafIJvYRdIZ+DDV0qDom15k97pLzcgnNjRtA/CKr
bd4M6qMUcKp6T99rEvRDWRlBEE1sTEa3OtA3tW+32pRMOzUBoUaLzPtXAxYJzzKx
lyIeRLAK8pxtOcwP0s9FQbNndmV08S0at5EZJzYLqN9yRuC+2It+5fvOUyIrcNGs
uFB52MIoy9JYWjIw2gdqjWXVRqV5SvWT4ftVjt43Lt/sjBrTiZrDSS6HpgbYw0CU
BsX0LKedLYER3SRfSKy7E/vAhOhAEINppakjFTPAtUAxTI4pSnvTxe4+9LTcqVQ4
UieQcDBFdqaLhW7kp6XpIdhyWylzzVepPBtMTwIDAQABAoIBACtNVIUTx8uIOMfz
bOMt8vRLTMMuYkzq8ejVLguCgyzdpy07ogNElUK6b9BUIWFmLHpgFb7kBSVvlgH2
6GCQfH9F8LC8eEXWbicguF9b+Uy+urxULYAlABzqk6CEqA+32UIZLAWGZQSkWwqo
AOzmGYAUNDIxaFD9buHdQoVVOV0G9Ypu2L7fadatjmAbWsd5VI888Dcps3zguMQW
RSk5z8ycebD1F0V6dgukTg6SWqOLXTM3I+XVzbdHBfXhNJ5KJ+DRCW53Oll+F8TN
miPOMMkWj6WvQJJSt+TWymEpbViTb9AOeZ+5tJfbFkr1QP14zO78aTuQMJNu4va1
Yi3VLGECgYEA8rmfsNYllb/a9hXaNdfUynjolsC59yiRMyM+6Zq6UxNGY15O0uoT
WevyjpcXc4pAhEE3tQa43TALXOJW3uYmtF49HlbB0kvj9aFTM/JOlFD3Y1DVPPpC
QrjKQFCjKJNtYRpuJ6U0skf0qdogEzPyV1hfg+V0UxYsaI1GxoOuy/ECgYEAyYqp
v+9VpV3zihzd72beVrwcVlcgqREGyGzap1J1hBHrh4eRbHfr7+aIaDjMFw7UOm8r
p7xlxO7XfmLdNL+/ULXYOYssXhWRabSmkO8K+jSe8/GdeWfFGLjHBCSj+XjUdvbj
1GiPbyKrptC2UsL8BO1XLm/kAfi4U6xzrY4U3D8CgYAnMhB2hu5E01lxea/mF/dV
xtaQWYjuP4/K+TsUkBbciXVJYJZL+t6rG63slruDveSTNtDfG7nIhhSfqDEtB29i
mwE1n/7mjbi/FpEQB2XnD3gTgp8cnLEMgzit0Be42q3EC3eUUVpEG9iHgSDC2RWe
QzgRXYE+VYtQStgOAH++kQKBgQDIfWuOZx1xKzw5eawCGvg1ml4qOfRgm3J+8WK2
rt3+qwD9ywwMtmN8PH4YB+BnU7YmBy+LZmxq8xpmPR1G+zTrqmpWHC/fzF7io/ZL
GbF249/4VrRL8MHubOp2IakJZH0fd01/oSCG8xuFD/0/6X5hvGVM6bwNhgqAGn7c
+QmhawKBgCUGxf5zYov6ZEVup06O/hlwAwMsq1vw2KPlwYMcjAKDj6rIz8mAZmT+
Yxty35glWR1l8sPN0rD9+QdEYuLY3Ov23SVxHnNKy1pGSJjTinBkfjNEBOdfDUrV
ga1bMw04tVw/6O9EEKNGaQsS6B0fzq99acgVHADvRji+eqw18x0J
-----END RSA PRIVATE KEY-----
`

const pemPKCS8RSAPrivateKey = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC/Fzdkc01Vp8gm
9hF0hn4MNXSoOibXmT3ukvNyCc2NG0D8Iqtt3gzqoxRwqnpP32sS9ENZGUEQTWxM
Rrc60De1b7falEw7NQGhRovM+1cDFgnPMrGXIh5EsArynG05zA/Sz0VBs2d2ZXTx
LRq3kRknNguo33JG4L7Yi37l+85TIitw0ay4UHnYwijL0lhaMjDaB2qNZdVGpXlK
9ZPh+1WO3jcu3+yMGtOJmsNJLoemBtjDQJQGxfQsp50tgRHdJF9IrLsT+8CE6EAQ
g2mlqSMVM8C1QDFMjilKe9PF7j70tNypVDhSJ5BwMEV2pouFbuSnpekh2HJbKXPN
V6k8G0xPAgMBAAECggEAK01UhRPHy4g4x/Ns4y3y9EtMwy5iTOrx6NUuC4KDLN2n
LTuiA0SVQrpv0FQhYWYsemAVvuQFJW+WAfboYJB8f0XwsLx4RdZuJyC4X1v5TL66
vFQtgCUAHOqToISoD7fZQhksBYZlBKRbCqgA7OYZgBQ0MjFoUP1u4d1ChVU5XQb1
im7Yvt9p1q2OYBtax3lUjzzwNymzfOC4xBZFKTnPzJx5sPUXRXp2C6RODpJao4td
Mzcj5dXNt0cF9eE0nkon4NEJbnc6WX4XxM2aI84wyRaPpa9AklK35NbKYSltWJNv
0A55n7m0l9sWSvVA/XjM7vxpO5Awk27i9rViLdUsYQKBgQDyuZ+w1iWVv9r2Fdo1
19TKeOiWwLn3KJEzIz7pmrpTE0ZjXk7S6hNZ6/KOlxdzikCEQTe1BrjdMAtc4lbe
5ia0Xj0eVsHSS+P1oVMz8k6UUPdjUNU8+kJCuMpAUKMok21hGm4npTSyR/Sp2iAT
M/JXWF+D5XRTFixojUbGg67L8QKBgQDJiqm/71WlXfOKHN3vZt5WvBxWVyCpEQbI
bNqnUnWEEeuHh5Fsd+vv5ohoOMwXDtQ6byunvGXE7td+Yt00v79Qtdg5iyxeFZFp
tKaQ7wr6NJ7z8Z15Z8UYuMcEJKP5eNR29uPUaI9vIqum0LZSwvwE7Vcub+QB+LhT
rHOtjhTcPwKBgCcyEHaG7kTTWXF5r+YX91XG1pBZiO4/j8r5OxSQFtyJdUlglkv6
3qsbreyWu4O95JM20N8buciGFJ+oMS0Hb2KbATWf/uaNuL8WkRAHZecPeBOCnxyc
sQyDOK3QF7jarcQLd5RRWkQb2IeBIMLZFZ5DOBFdgT5Vi1BK2A4Af76RAoGBAMh9
a45nHXErPDl5rAIa+DWaXio59GCbcn7xYrau3f6rAP3LDAy2Y3w8fhgH4GdTtiYH
L4tmbGrzGmY9HUb7NOuqalYcL9/MXuKj9ksZsXbj3/hWtEvwwe5s6nYhqQlkfR93
TX+hIIbzG4UP/T/pfmG8ZUzpvA2GCoAaftz5CaFrAoGAJQbF/nNii/pkRW6nTo7+
GXADAyyrW/DYo+XBgxyMAoOPqsjPyYBmZP5jG3LfmCVZHWXyw83SsP35B0Ri4tjc
6/bdJXEec0rLWkZImNOKcGR+M0QE518NStWBrVszDTi1XD/o70QQo0ZpCxLoHR/O
r31pyBUcAO9GOL56rDXzHQk=
-----END PRIVATE KEY-----
`
