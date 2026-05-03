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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	x509pkix "crypto/x509/pkix"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/pkix"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

type testSigner struct{}

func (s testSigner) Public() crypto.PublicKey { return nil }

func (s testSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, nil }

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
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed to get information")
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
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "is not a file")
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
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "no key material present")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			ks, err := newKeyStoreFromPEMFile("test", tc.pemFile(t), "")
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
				assert.IsType(t, &ecdsa.PrivateKey{}, ks[0].Signer())
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
				require.ErrorIs(t, err, pipeline.ErrInternal)
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
				require.ErrorIs(t, err, pipeline.ErrInternal)
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
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "duplicate entry for key_id=dup")
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
				assert.Equal(t, hex.EncodeToString(ks[0].CertChain()[0].SubjectKeyId), ks[0].KeyID())
				assert.Len(t, ks[0].CertChain(), 2)
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

				expectedKid, err := pkix.SubjectKeyID(ks[0].Signer().Public())
				require.NoError(t, err)
				assert.Equal(t, hex.EncodeToString(expectedKid), ks[0].KeyID())
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
				assert.Equal(t, "custom-kid", ks[0].KeyID())
				assert.Equal(t, ks[0].Ref(), ks[0].KeyID())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			ks, err := newKeyStoreFromPEMBytes("test", tc.pemBytes(t), tc.password)
			tc.assert(t, ks, err)
		})
	}
}

func TestNewKeyStoreFromKey(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		key    func(*testing.T) crypto.Signer
		assert func(*testing.T, keyStore, error)
	}{
		"creates store for rsa key": {
			key: func(t *testing.T) crypto.Signer {
				t.Helper()

				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				return key
			},
			assert: func(t *testing.T, ks keyStore, err error) {
				t.Helper()
				require.NoError(t, err)
				require.Len(t, ks, 1)

				assert.Equal(t, types.SecretKindSigner, ks[0].Kind())
				assert.IsType(t, &rsa.PrivateKey{}, ks[0].Signer())
				assert.NotEmpty(t, ks[0].KeyID())
				assert.Equal(t, ks[0].Ref(), ks[0].KeyID())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			ks, err := newKeyStoreFromKey("test", "test", tc.key(t))
			tc.assert(t, ks, err)
		})
	}
}

func TestKeyStoreGet(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pemBytes, err := pemx.BuildPEM(pemx.WithRSAPrivateKey(key, pemx.WithHeader("X-Key-ID", "first")))
	require.NoError(t, err)

	ks, err := newKeyStoreFromPEMBytes("test", pemBytes, "")
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
				require.ErrorIs(t, err, errNoSuchKey)
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

const pemPKCS8ECEncryptedPrivateKey = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAiJ8VMMyD9LkQICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEDM4MvufeWaeKFIyuILKBAYEgZC0
iSSw1qwqVWxIik/YWxn90MvvNCg9P1MHyF2i5w7Xp+uPFjRM4o+7PdHhRgJSnsDT
6JYTU6S5Gdl6t5JsFqhIBDYyqrs/+cegw0dSGl/B/UoZ0taNK66RKQ6wuv/VCcuY
MtusvyePIsJKGGKsTyHwla4eWpjorL+V116zP35J5x32AFIT8hCbZlLGdL5dpVU=
-----END ENCRYPTED PRIVATE KEY-----
`
