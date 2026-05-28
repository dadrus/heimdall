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

package keyregistry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

type RegistryTestSuite struct {
	suite.Suite

	rootCA1 *testsupport.CA
	intCA1  *testsupport.CA
	intCA2  *testsupport.CA
	ee1     *testsupport.EndEntity
	ee2     *testsupport.EndEntity
	ee3     *testsupport.EndEntity
}

func TestRegistryTestSuite(t *testing.T) {
	suite.Run(t, new(RegistryTestSuite))
}

func (s *RegistryTestSuite) SetupSuite() {
	var err error

	// ROOT CA
	s.rootCA1, err = testsupport.NewRootCA("Test Root CA 1", time.Hour*24)
	s.Require().NoError(err)

	// INT CAs
	intCA1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	s.Require().NoError(err)

	intCA1Cert, err := s.rootCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test Int CA 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithIsCA(),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&intCA1PrivKey.PublicKey, x509.ECDSAWithSHA384),
	)
	s.Require().NoError(err)

	s.intCA1 = testsupport.NewCA(intCA1PrivKey, intCA1Cert)

	intCA2PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	s.Require().NoError(err)

	intCA2Cert, err := s.rootCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test Int CA 2",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithIsCA(),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithGeneratedSubjectKeyID(),
		testsupport.WithSubjectPubKey(&intCA2PrivKey.PublicKey, x509.ECDSAWithSHA384),
	)
	s.Require().NoError(err)

	s.intCA2 = testsupport.NewCA(intCA2PrivKey, intCA2Cert)

	// EE CERTS
	ee1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	s.Require().NoError(err)

	ee1Cert, err := s.intCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&ee1PrivKey.PublicKey, x509.ECDSAWithSHA384),
	)
	s.Require().NoError(err)

	s.ee1 = &testsupport.EndEntity{
		Certificate: ee1Cert,
		PrivKey:     ee1PrivKey,
	}

	ee2PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	s.Require().NoError(err)

	ee2Cert, err := s.intCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 2",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now().Add(-time.Hour*24), time.Hour),
		testsupport.WithSubjectPubKey(&ee2PrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithGeneratedSubjectKeyID(),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
	)
	s.Require().NoError(err)

	s.ee2 = &testsupport.EndEntity{
		Certificate: ee2Cert,
		PrivKey:     ee2PrivKey,
	}

	ee3PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	s.Require().NoError(err)

	ee3Cert, err := s.intCA2.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 3",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour),
		testsupport.WithSubjectPubKey(&ee3PrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithGeneratedSubjectKeyID(),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
	)
	s.Require().NoError(err)

	s.ee3 = &testsupport.EndEntity{
		Certificate: ee3Cert,
		PrivKey:     ee3PrivKey,
	}
}

func (s *RegistryTestSuite) TestKeysNoAllocs() {
	// GIVEN
	reg, err := newRegistry()
	s.Require().NoError(err)

	reg.Notify(types.NewAsymmetricKeySecret(
		"kid-1",
		"kid-1",
		s.ee1.PrivKey,
		[]*x509.Certificate{s.ee1.Certificate},
	))

	// WHEN
	allocs := testing.AllocsPerRun(1000, func() {
		_ = reg.Keys()
	})

	// THEN
	s.Equal(0, int(allocs))
}

func (s *RegistryTestSuite) TestNotify() {
	for uc, tc := range map[string]struct {
		events []types.AsymmetricKeySecret
		assert func(t *testing.T, reg *registry)
	}{
		"single certificate added": {
			events: []types.AsymmetricKeySecret{
				types.NewAsymmetricKeySecret(
					"kid-1",
					"kid-1",
					s.ee1.PrivKey,
					[]*x509.Certificate{s.ee1.Certificate},
				),
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				require.Len(t, reg.keys, 1)
				assert.Contains(t, reg.keys, "kid-1")

				require.Len(t, reg.snapshot, 1)
				assert.Equal(t, "kid-1", reg.snapshot[0].KeyID)
				assert.Equal(t, s.ee1.Certificate.PublicKey, reg.snapshot[0].Key)
				assert.Len(t, reg.snapshot[0].Certificates, 1)
				assert.Equal(t, s.ee1.Certificate, reg.snapshot[0].Certificates[0])
				assert.Equal(t, string(jose.ES384), reg.snapshot[0].Algorithm)
				assert.Equal(t, "sig", reg.snapshot[0].Use)
			},
		},
		"multiple certificates with chains added": {
			events: []types.AsymmetricKeySecret{
				types.NewAsymmetricKeySecret(
					"kid-1",
					"kid-1",
					s.ee1.PrivKey,
					[]*x509.Certificate{s.ee1.Certificate, s.intCA1.Certificate, s.rootCA1.Certificate},
				),
				types.NewAsymmetricKeySecret(
					"kid-2",
					"kid-2",
					s.ee2.PrivKey,
					[]*x509.Certificate{s.ee2.Certificate, s.intCA1.Certificate, s.rootCA1.Certificate},
				),
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				require.Len(t, reg.keys, 2)
				assert.Contains(t, reg.keys, "kid-1")
				assert.Contains(t, reg.keys, "kid-2")

				require.Len(t, reg.snapshot, 2)

				assert.Equal(t, "kid-1", reg.snapshot[0].KeyID)
				assert.Equal(t, s.ee1.Certificate.PublicKey, reg.snapshot[0].Key)
				assert.Len(t, reg.snapshot[0].Certificates, 3)
				assert.Equal(t, s.ee1.Certificate, reg.snapshot[0].Certificates[0])
				assert.Equal(t, s.intCA1.Certificate, reg.snapshot[0].Certificates[1])
				assert.Equal(t, s.rootCA1.Certificate, reg.snapshot[0].Certificates[2])

				assert.Equal(t, "kid-2", reg.snapshot[1].KeyID)
				assert.Equal(t, s.ee2.Certificate.PublicKey, reg.snapshot[1].Key)
				assert.Len(t, reg.snapshot[1].Certificates, 3)
				assert.Equal(t, s.ee2.Certificate, reg.snapshot[1].Certificates[0])
				assert.Equal(t, s.intCA1.Certificate, reg.snapshot[1].Certificates[1])
				assert.Equal(t, s.rootCA1.Certificate, reg.snapshot[1].Certificates[2])
			},
		},
		"certificate updated": {
			events: []types.AsymmetricKeySecret{
				types.NewAsymmetricKeySecret(
					"kid-1",
					"kid-1",
					s.ee1.PrivKey,
					[]*x509.Certificate{s.ee1.Certificate, s.intCA1.Certificate},
				),
				types.NewAsymmetricKeySecret(
					"kid-1",
					"kid-1",
					s.ee3.PrivKey,
					[]*x509.Certificate{s.ee3.Certificate, s.intCA2.Certificate},
				),
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				require.Len(t, reg.keys, 1)
				assert.Contains(t, reg.keys, "kid-1")

				secret := reg.keys["kid-1"]
				assert.Equal(t, s.ee3.PrivKey.Public(), secret.PrivateKey().Public())
				assert.Equal(t, []*x509.Certificate{s.ee3.Certificate, s.intCA2.Certificate}, secret.CertChain())

				require.Len(t, reg.snapshot, 1)
				assert.Equal(t, "kid-1", reg.snapshot[0].KeyID)
				assert.Equal(t, s.ee3.Certificate.PublicKey, reg.snapshot[0].Key)
				assert.Len(t, reg.snapshot[0].Certificates, 2)
				assert.Equal(t, s.ee3.Certificate, reg.snapshot[0].Certificates[0])
				assert.Equal(t, s.intCA2.Certificate, reg.snapshot[0].Certificates[1])
			},
		},
		"same certificate added multiple times": {
			events: []types.AsymmetricKeySecret{
				types.NewAsymmetricKeySecret(
					"kid-1",
					"kid-1",
					s.ee1.PrivKey,
					[]*x509.Certificate{s.ee1.Certificate},
				),
				types.NewAsymmetricKeySecret(
					"kid-1",
					"kid-1",
					s.ee1.PrivKey,
					[]*x509.Certificate{s.ee1.Certificate},
				),
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				require.Len(t, reg.keys, 1)
				assert.Contains(t, reg.keys, "kid-1")

				require.Len(t, reg.snapshot, 1)
				assert.Equal(t, "kid-1", reg.snapshot[0].KeyID)
				assert.Equal(t, s.ee1.Certificate.PublicKey, reg.snapshot[0].Key)
				assert.Len(t, reg.snapshot[0].Certificates, 1)
				assert.Equal(t, s.ee1.Certificate, reg.snapshot[0].Certificates[0])
			},
		},
		"single key without certificate chain added": {
			events: []types.AsymmetricKeySecret{
				types.NewAsymmetricKeySecret(
					"kid-1",
					"kid-1",
					s.ee1.PrivKey,
					nil,
				),
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				require.Len(t, reg.keys, 1)
				assert.Contains(t, reg.keys, "kid-1")

				secret := reg.keys["kid-1"]
				assert.Equal(t, s.ee1.Certificate.PublicKey, secret.PrivateKey().Public())
				assert.Empty(t, secret.CertChain())

				require.Len(t, reg.snapshot, 1)
				assert.Equal(t, "kid-1", reg.snapshot[0].KeyID)
				assert.Equal(t, s.ee1.Certificate.PublicKey, reg.snapshot[0].Key)
				assert.Empty(t, reg.snapshot[0].Certificates)
				assert.Equal(t, string(jose.ES384), reg.snapshot[0].Algorithm)
				assert.Equal(t, "sig", reg.snapshot[0].Use)
			},
		},
		"single key without certificate chain updated": {
			events: []types.AsymmetricKeySecret{
				types.NewAsymmetricKeySecret(
					"kid-1",
					"kid-1",
					s.ee1.PrivKey,
					nil,
				),
				types.NewAsymmetricKeySecret(
					"kid-1",
					"kid-1",
					s.ee2.PrivKey,
					nil,
				),
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				require.Len(t, reg.keys, 1)
				assert.Contains(t, reg.keys, "kid-1")

				secret := reg.keys["kid-1"]
				assert.Equal(t, s.ee2.PrivKey.Public(), secret.PrivateKey().Public())
				assert.Empty(t, secret.CertChain())

				require.Len(t, reg.snapshot, 1)
				assert.Equal(t, "kid-1", reg.snapshot[0].KeyID)
				assert.Equal(t, s.ee2.PrivKey.Public(), reg.snapshot[0].Key)
				assert.Empty(t, reg.snapshot[0].Certificates)
				assert.Equal(t, string(jose.ES384), reg.snapshot[0].Algorithm)
				assert.Equal(t, "sig", reg.snapshot[0].Use)
			},
		},
		"keys are exposed in deterministic key id order": {
			events: []types.AsymmetricKeySecret{
				types.NewAsymmetricKeySecret(
					"kid-2",
					"kid-2",
					s.ee2.PrivKey,
					nil,
				),
				types.NewAsymmetricKeySecret(
					"kid-1",
					"kid-1",
					s.ee1.PrivKey,
					nil,
				),
				types.NewAsymmetricKeySecret(
					"kid-3",
					"kid-3",
					s.ee3.PrivKey,
					nil,
				),
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				require.Len(t, reg.keys, 3)
				assert.Contains(t, reg.keys, "kid-1")
				assert.Contains(t, reg.keys, "kid-2")
				assert.Contains(t, reg.keys, "kid-3")

				require.Len(t, reg.snapshot, 3)
				assert.Equal(t, "kid-1", reg.snapshot[0].KeyID)
				assert.Equal(t, "kid-2", reg.snapshot[1].KeyID)
				assert.Equal(t, "kid-3", reg.snapshot[2].KeyID)
			},
		},
	} {
		s.Run(uc, func() {
			// GIVEN
			reg, err := newRegistry()
			s.Require().NoError(err)

			// WHEN
			for _, event := range tc.events {
				reg.Notify(event)
			}

			// THEN
			tc.assert(s.T(), reg.(*registry))
		})
	}
}
