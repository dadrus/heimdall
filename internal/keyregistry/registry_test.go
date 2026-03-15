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
	"math/big"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

type RegistryTestSuite struct {
	suite.Suite

	rootCA1        *testsupport.CA
	intCA1         *testsupport.CA
	intCA2         *testsupport.CA
	ee1            *testsupport.EndEntity
	ee2            *testsupport.EndEntity
	ee3            *testsupport.EndEntity
	ee4            *testsupport.EndEntity
	selfSignedCert *testsupport.EndEntity
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
		testsupport.WithSubjectPubKey(&intCA1PrivKey.PublicKey, x509.ECDSAWithSHA384))
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
		testsupport.WithSubjectPubKey(&intCA2PrivKey.PublicKey, x509.ECDSAWithSHA384))
	s.Require().NoError(err)
	s.intCA2 = testsupport.NewCA(intCA2PrivKey, intCA2Cert)

	// EE CERTS
	ee1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	s.Require().NoError(err)
	ee1cert, err := s.intCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&ee1PrivKey.PublicKey, x509.ECDSAWithSHA384))
	s.Require().NoError(err)
	s.ee1 = &testsupport.EndEntity{Certificate: ee1cert, PrivKey: ee1PrivKey}

	ee2PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	s.Require().NoError(err)
	ee2cert, err := s.intCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 2",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now().Add(-time.Hour*24), time.Hour*1),
		testsupport.WithSubjectPubKey(&ee2PrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithGeneratedSubjectKeyID(),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
	s.Require().NoError(err)
	s.ee2 = &testsupport.EndEntity{Certificate: ee2cert, PrivKey: ee2PrivKey}

	ee3PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	s.Require().NoError(err)
	ee3cert, err := s.intCA2.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 3",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour*1),
		testsupport.WithSubjectPubKey(&ee3PrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithGeneratedSubjectKeyID(),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
	s.Require().NoError(err)
	s.ee3 = &testsupport.EndEntity{Certificate: ee3cert, PrivKey: ee3PrivKey}

	ee4PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	s.Require().NoError(err)
	ee4cert, err := s.intCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 4",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now().Add(-2*time.Hour), 1*time.Hour),
		testsupport.WithSubjectPubKey(&ee4PrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithGeneratedSubjectKeyID(),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
	s.Require().NoError(err)
	s.ee4 = &testsupport.EndEntity{Certificate: ee4cert, PrivKey: ee4PrivKey}

	selfSignedCertPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	s.Require().NoError(err)

	selfSignedCert, err := testsupport.NewCertificateBuilder(
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "self signed",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&selfSignedCertPrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSignaturePrivKey(selfSignedCertPrivKey),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
		testsupport.WithGeneratedSubjectKeyID(),
		testsupport.WithSelfSigned(),
	).Build()
	s.Require().NoError(err)
	s.selfSignedCert = &testsupport.EndEntity{Certificate: selfSignedCert, PrivKey: selfSignedCertPrivKey}
}

func (s *RegistryTestSuite) TestKeysNoAllocs() {
	// GIVEN
	reg, err := newRegistry(noop.Meter{})
	s.Require().NoError(err)

	reg.Notify(KeyInfo{
		Entry: keystore.Entry{
			Alg:       keystore.AlgECDSA,
			KeySize:   384,
			KeyID:     "kid-1",
			CertChain: []*x509.Certificate{s.ee1.Certificate},
		},
		Exportable: true,
	})

	// WHEN
	allocs := testing.AllocsPerRun(1000, func() {
		_ = reg.Keys()
	})

	// THEN
	s.Equal(0, int(allocs))
}

func (s *RegistryTestSuite) TestNotify() {
	for uc, tc := range map[string]struct {
		events []KeyInfo
		assert func(t *testing.T, reg *registry)
	}{
		"single exportable certificate added": {
			events: []KeyInfo{
				{
					Entry: keystore.Entry{
						KeyID:      "kid-1",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee1.PrivKey,
						CertChain:  []*x509.Certificate{s.ee1.Certificate},
					},
					Exportable: true,
				},
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				require.Len(t, reg.state, 1)
				assert.Contains(t, reg.state, "kid-1")

				require.Len(t, reg.keysSnapshot, 1)
				assert.Equal(t, "kid-1", reg.keysSnapshot[0].KeyID)

				assert.Len(t, reg.metricsState, 1)
				ms := reg.metricsState[createCertID(s.ee1.Certificate)]
				assert.Equal(t, 1, ms.refCount)
				assert.Equal(t, s.ee1.Certificate.NotAfter, ms.notAfter)
				assert.Equal(t, 4, ms.attrs.Len())

				val, present := ms.attrs.Value(certificateIssuerKey)
				assert.True(t, present)
				assert.Equal(t, "CN=Test Int CA 1,O=Test,C=EU", val.AsString())

				val, present = ms.attrs.Value(certificateSerialNumberKey)
				assert.True(t, present)
				assert.Equal(t, "1001", val.AsString())

				val, present = ms.attrs.Value(certificateDNSNameKey)
				assert.True(t, present)
				assert.Empty(t, val.AsString())

				val, present = ms.attrs.Value(certificateSubjectKey)
				assert.True(t, present)
				assert.Equal(t, "CN=Test EE 1,O=Test,C=EU", val.AsString())
			},
		},
		"single not exportable certificate added": {
			events: []KeyInfo{
				{
					Entry: keystore.Entry{
						KeyID:      "kid-1",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee1.PrivKey,
						CertChain:  []*x509.Certificate{s.ee1.Certificate},
					},
					Exportable: false,
				},
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				require.Len(t, reg.state, 1)
				assert.Contains(t, reg.state, "kid-1")

				require.Empty(t, reg.keysSnapshot)

				assert.Len(t, reg.metricsState, 1)
				ms := reg.metricsState[createCertID(s.ee1.Certificate)]
				assert.Equal(t, 1, ms.refCount)
				assert.Equal(t, s.ee1.Certificate.NotAfter, ms.notAfter)
				assert.Equal(t, 4, ms.attrs.Len())

				val, present := ms.attrs.Value(certificateIssuerKey)
				assert.True(t, present)
				assert.Equal(t, "CN=Test Int CA 1,O=Test,C=EU", val.AsString())

				val, present = ms.attrs.Value(certificateSerialNumberKey)
				assert.True(t, present)
				assert.Equal(t, "1001", val.AsString())

				val, present = ms.attrs.Value(certificateDNSNameKey)
				assert.True(t, present)
				assert.Empty(t, val.AsString())

				val, present = ms.attrs.Value(certificateSubjectKey)
				assert.True(t, present)
				assert.Equal(t, "CN=Test EE 1,O=Test,C=EU", val.AsString())
			},
		},
		"multiple certificates with overlapping key chains added, with one being exportable": {
			events: []KeyInfo{
				{
					Entry: keystore.Entry{
						KeyID:      "kid-1",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee1.PrivKey,
						CertChain:  []*x509.Certificate{s.ee1.Certificate, s.intCA1.Certificate, s.rootCA1.Certificate},
					},
					Exportable: false,
				},
				{
					Entry: keystore.Entry{
						KeyID:      "kid-2",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee2.PrivKey,
						CertChain:  []*x509.Certificate{s.ee2.Certificate, s.intCA1.Certificate, s.rootCA1.Certificate},
					},
					Exportable: true,
				},
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				require.Len(t, reg.state, 2)
				assert.Contains(t, reg.state, "kid-1")
				assert.Contains(t, reg.state, "kid-2")

				require.Len(t, reg.keysSnapshot, 1)
				assert.Equal(t, "kid-2", reg.keysSnapshot[0].KeyID)

				assert.Len(t, reg.metricsState, 4)

				// ee1 certs metrics data
				ms := reg.metricsState[createCertID(s.ee1.Certificate)]
				assert.Equal(t, 1, ms.refCount)
				assert.Equal(t, s.ee1.Certificate.NotAfter, ms.notAfter)
				assert.Equal(t, 4, ms.attrs.Len())

				val, present := ms.attrs.Value(certificateIssuerKey)
				assert.True(t, present)
				assert.Equal(t, "CN=Test Int CA 1,O=Test,C=EU", val.AsString())

				val, present = ms.attrs.Value(certificateSerialNumberKey)
				assert.True(t, present)
				assert.Equal(t, "1001", val.AsString())

				val, present = ms.attrs.Value(certificateDNSNameKey)
				assert.True(t, present)
				assert.Empty(t, val.AsString())

				val, present = ms.attrs.Value(certificateSubjectKey)
				assert.True(t, present)
				assert.Equal(t, "CN=Test EE 1,O=Test,C=EU", val.AsString())

				// ee2 certs metrics data
				ms = reg.metricsState[createCertID(s.ee2.Certificate)]
				assert.Equal(t, 1, ms.refCount)
				assert.Equal(t, s.ee2.Certificate.NotAfter, ms.notAfter)
				assert.Equal(t, 4, ms.attrs.Len())

				val, present = ms.attrs.Value(certificateIssuerKey)
				assert.True(t, present)
				assert.Equal(t, "CN=Test Int CA 1,O=Test,C=EU", val.AsString())

				val, present = ms.attrs.Value(certificateSerialNumberKey)
				assert.True(t, present)
				assert.Equal(t, "1002", val.AsString())

				val, present = ms.attrs.Value(certificateDNSNameKey)
				assert.True(t, present)
				assert.Empty(t, val.AsString())

				val, present = ms.attrs.Value(certificateSubjectKey)
				assert.True(t, present)
				assert.Equal(t, "CN=Test EE 2,O=Test,C=EU", val.AsString())

				// int ca1 certs metrics data
				ms = reg.metricsState[createCertID(s.intCA1.Certificate)]
				assert.Equal(t, 2, ms.refCount)
				assert.Equal(t, s.intCA1.Certificate.NotAfter, ms.notAfter)
				assert.Equal(t, 4, ms.attrs.Len())

				val, present = ms.attrs.Value(certificateIssuerKey)
				assert.True(t, present)
				assert.Equal(t, "CN=Test Root CA 1,O=Test,C=EU", val.AsString())

				val, present = ms.attrs.Value(certificateSerialNumberKey)
				assert.True(t, present)
				assert.Equal(t, "1001", val.AsString())

				val, present = ms.attrs.Value(certificateDNSNameKey)
				assert.True(t, present)
				assert.Empty(t, val.AsString())

				val, present = ms.attrs.Value(certificateSubjectKey)
				assert.True(t, present)
				assert.Equal(t, "CN=Test Int CA 1,O=Test,C=EU", val.AsString())

				// root ca1 certs metrics data
				ms = reg.metricsState[createCertID(s.rootCA1.Certificate)]
				assert.Equal(t, 2, ms.refCount)
				assert.Equal(t, s.intCA1.Certificate.NotAfter, ms.notAfter)
				assert.Equal(t, 4, ms.attrs.Len())

				val, present = ms.attrs.Value(certificateIssuerKey)
				assert.True(t, present)
				assert.Equal(t, "CN=Test Root CA 1,O=Test,C=EU", val.AsString())

				val, present = ms.attrs.Value(certificateSerialNumberKey)
				assert.True(t, present)
				assert.Equal(t, "1", val.AsString())

				val, present = ms.attrs.Value(certificateDNSNameKey)
				assert.True(t, present)
				assert.Empty(t, val.AsString())

				val, present = ms.attrs.Value(certificateSubjectKey)
				assert.True(t, present)
				assert.Equal(t, "CN=Test Root CA 1,O=Test,C=EU", val.AsString())
			},
		},
		"exportable certificate updated": {
			events: []KeyInfo{
				{
					Entry: keystore.Entry{
						KeyID:      "kid-1",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee1.PrivKey,
						CertChain:  []*x509.Certificate{s.ee1.Certificate, s.intCA1.Certificate},
					},
					Exportable: true,
				},
				{
					Entry: keystore.Entry{
						KeyID:      "kid-1",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee3.PrivKey,
						CertChain:  []*x509.Certificate{s.ee3.Certificate, s.intCA2.Certificate},
					},
					Exportable: true,
				},
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				require.Len(t, reg.state, 1)
				assert.Contains(t, reg.state, "kid-1")

				require.Len(t, reg.keysSnapshot, 1)
				assert.Equal(t, "kid-1", reg.keysSnapshot[0].KeyID)

				assert.Len(t, reg.metricsState, 2)

				// ee3 certs metrics data
				ms := reg.metricsState[createCertID(s.ee3.Certificate)]
				assert.Equal(t, 1, ms.refCount)
				assert.Equal(t, s.ee3.Certificate.NotAfter, ms.notAfter)
				assert.Equal(t, 4, ms.attrs.Len())

				val, present := ms.attrs.Value(certificateIssuerKey)
				assert.True(t, present)
				assert.Equal(t, "CN=Test Int CA 2,O=Test,C=EU", val.AsString())

				val, present = ms.attrs.Value(certificateSerialNumberKey)
				assert.True(t, present)
				assert.Equal(t, "1001", val.AsString())

				val, present = ms.attrs.Value(certificateDNSNameKey)
				assert.True(t, present)
				assert.Empty(t, val.AsString())

				val, present = ms.attrs.Value(certificateSubjectKey)
				assert.True(t, present)
				assert.Equal(t, "CN=Test EE 3,O=Test,C=EU", val.AsString())

				// int ca2 certs metrics data
				ms = reg.metricsState[createCertID(s.intCA2.Certificate)]
				assert.Equal(t, 1, ms.refCount)
				assert.Equal(t, s.intCA2.Certificate.NotAfter, ms.notAfter)
				assert.Equal(t, 4, ms.attrs.Len())

				val, present = ms.attrs.Value(certificateIssuerKey)
				assert.True(t, present)
				assert.Equal(t, "CN=Test Root CA 1,O=Test,C=EU", val.AsString())

				val, present = ms.attrs.Value(certificateSerialNumberKey)
				assert.True(t, present)
				assert.Equal(t, "1002", val.AsString())

				val, present = ms.attrs.Value(certificateDNSNameKey)
				assert.True(t, present)
				assert.Empty(t, val.AsString())

				val, present = ms.attrs.Value(certificateSubjectKey)
				assert.True(t, present)
				assert.Equal(t, "CN=Test Int CA 2,O=Test,C=EU", val.AsString())
			},
		},
		"same not exportable certificate added multiple times": {
			events: []KeyInfo{
				{
					Entry: keystore.Entry{
						KeyID:      "kid-1",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee1.PrivKey,
						CertChain:  []*x509.Certificate{s.ee1.Certificate},
					},
					Exportable: false,
				},
				{
					Entry: keystore.Entry{
						KeyID:      "kid-1",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee1.PrivKey,
						CertChain:  []*x509.Certificate{s.ee1.Certificate},
					}, Exportable: false,
				},
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				// the effect must be the same as in "single not exportable certificate added" test
				require.Len(t, reg.state, 1)
				assert.Contains(t, reg.state, "kid-1")

				require.Empty(t, reg.keysSnapshot)

				assert.Len(t, reg.metricsState, 1)
				ms := reg.metricsState[createCertID(s.ee1.Certificate)]
				assert.Equal(t, 1, ms.refCount)
				assert.Equal(t, s.ee1.Certificate.NotAfter, ms.notAfter)
				assert.Equal(t, 4, ms.attrs.Len())
			},
		},
		"same certificate added multiple times but one time exportable and one time not": {
			events: []KeyInfo{
				{
					Entry: keystore.Entry{
						KeyID:      "kid-1",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee1.PrivKey,
						CertChain:  []*x509.Certificate{s.ee1.Certificate},
					},
					Exportable: true,
				},
				{
					Entry: keystore.Entry{
						KeyID:      "kid-1",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee1.PrivKey,
						CertChain:  []*x509.Certificate{s.ee1.Certificate},
					},
					Exportable: true,
				},
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				// the effect must be the same as in "single exportable certificate added" test
				// the certificate is exportable
				require.Len(t, reg.state, 1)
				assert.Contains(t, reg.state, "kid-1")

				require.Len(t, reg.keysSnapshot, 1)
				assert.Equal(t, "kid-1", reg.keysSnapshot[0].KeyID)
				assert.Equal(t, s.ee1.Certificate.PublicKey, reg.keysSnapshot[0].Key)

				assert.Len(t, reg.metricsState, 1)
				ms := reg.metricsState[createCertID(s.ee1.Certificate)]
				assert.Equal(t, 1, ms.refCount)
				assert.Equal(t, s.ee1.Certificate.NotAfter, ms.notAfter)
				assert.Equal(t, 4, ms.attrs.Len())
			},
		},
		"single exportable key added": {
			events: []KeyInfo{
				{
					Entry: keystore.Entry{
						KeyID:      "kid-1",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee1.PrivKey,
					},
					Exportable: true,
				},
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				require.Len(t, reg.state, 1)
				assert.Contains(t, reg.state, "kid-1")
				ki := reg.state["kid-1"]
				assert.Equal(t, s.ee1.Certificate.PublicKey, ki.JWK().Key)
				assert.True(t, reg.state["kid-1"].Exportable)
				assert.Empty(t, reg.state["kid-1"].CertChain)

				require.Len(t, reg.keysSnapshot, 1)
				assert.Equal(t, "kid-1", reg.keysSnapshot[0].KeyID)
				assert.Equal(t, s.ee1.Certificate.PublicKey, reg.keysSnapshot[0].Key)
				assert.Empty(t, reg.keysSnapshot[0].Certificates)

				assert.Empty(t, reg.metricsState)
			},
		},
		"single not exportable key added": {
			events: []KeyInfo{
				{
					Entry: keystore.Entry{
						KeyID:      "kid-1",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee1.PrivKey,
					},
					Exportable: false,
				},
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				require.Len(t, reg.state, 1)
				assert.Contains(t, reg.state, "kid-1")

				assert.Empty(t, reg.keysSnapshot)

				// No metrics for just a key
				assert.Empty(t, reg.metricsState)
			},
		},
		"single exportable key updated": {
			events: []KeyInfo{
				{
					Entry: keystore.Entry{
						KeyID:      "kid-1",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee1.PrivKey,
					},
					Exportable: true,
				},
				{
					Entry: keystore.Entry{
						KeyID:      "kid-1",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee2.PrivKey,
					},
					Exportable: true,
				},
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				require.Len(t, reg.state, 1)
				assert.Contains(t, reg.state, "kid-1")

				assert.Len(t, reg.keysSnapshot, 1)
				assert.Equal(t, "kid-1", reg.keysSnapshot[0].KeyID)
				assert.Equal(t, s.ee2.PrivKey.Public(), reg.keysSnapshot[0].Key)
				assert.Equal(t, string(jose.ES384), reg.keysSnapshot[0].Algorithm)
				assert.Equal(t, "sig", reg.keysSnapshot[0].Use)

				assert.Empty(t, reg.metricsState)
			},
		},
	} {
		s.Run(uc, func() {
			// GIVEN
			reg, err := newRegistry(noop.Meter{})
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

func (s *RegistryTestSuite) TestMetricsCollection() {
	for uc, tc := range map[string]struct {
		events []KeyInfo
		assert func(t *testing.T, dp []metricdata.DataPoint[float64])
	}{
		"without events": {
			assert: func(t *testing.T, dp []metricdata.DataPoint[float64]) {
				t.Helper()

				require.Empty(t, dp)
			},
		},
		"single chain reports expected datapoints and attributes": {
			events: []KeyInfo{
				{
					Entry: keystore.Entry{
						KeyID:      "kid-m-1",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee1.PrivKey,
						CertChain:  []*x509.Certificate{s.ee1.Certificate, s.intCA1.Certificate, s.rootCA1.Certificate},
					},
					Exportable: true,
				},
			},
			assert: func(t *testing.T, dp []metricdata.DataPoint[float64]) {
				t.Helper()

				require.Len(t, dp, 3)
				assertDataPointForCertificate(t, dp, s.ee1.Certificate)
				assertDataPointForCertificate(t, dp, s.intCA1.Certificate)
				assertDataPointForCertificate(t, dp, s.rootCA1.Certificate)
			},
		},
		"overlapping chains are deduplicated": {
			events: []KeyInfo{
				{
					Entry: keystore.Entry{
						KeyID:      "kid-m-2",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee1.PrivKey,
						CertChain:  []*x509.Certificate{s.ee1.Certificate, s.intCA1.Certificate, s.rootCA1.Certificate, s.ee1.Certificate},
					},
					Exportable: true,
				},
				{
					Entry: keystore.Entry{
						KeyID:      "kid-m-3",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee2.PrivKey,
						CertChain:  []*x509.Certificate{s.ee2.Certificate, s.intCA1.Certificate, s.rootCA1.Certificate, s.ee1.Certificate},
					},
					Exportable: true,
				},
			},
			assert: func(t *testing.T, dp []metricdata.DataPoint[float64]) {
				t.Helper()

				require.Len(t, dp, 4)
				assertDataPointForCertificate(t, dp, s.ee1.Certificate)
				assertDataPointForCertificate(t, dp, s.ee2.Certificate)
				assertDataPointForCertificate(t, dp, s.intCA1.Certificate)
				assertDataPointForCertificate(t, dp, s.rootCA1.Certificate)
			},
		},
		"updated exposes only final chain in metrics": {
			events: []KeyInfo{
				{
					Entry: keystore.Entry{
						KeyID:      "kid-m-4",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee1.PrivKey,
						CertChain:  []*x509.Certificate{s.ee1.Certificate},
					},
					Exportable: false,
				},
				{
					Entry: keystore.Entry{
						KeyID:      "kid-m-4",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee2.PrivKey,
						CertChain:  []*x509.Certificate{s.ee2.Certificate},
					},
					Exportable: false,
				},
			},
			assert: func(t *testing.T, dp []metricdata.DataPoint[float64]) {
				t.Helper()

				require.Len(t, dp, 1)
				assertDataPointForCertificate(t, dp, s.ee2.Certificate)
				assert.Empty(t, dataPointsForCertificate(s.ee1.Certificate, dp))
			},
		},
		"expired certificate reports negative expiry": {
			events: []KeyInfo{
				{
					Entry: keystore.Entry{
						KeyID:      "kid-m-5",
						Alg:        keystore.AlgECDSA,
						KeySize:    384,
						PrivateKey: s.ee4.PrivKey,
						CertChain:  []*x509.Certificate{s.ee4.Certificate},
					},
					Exportable: false,
				},
			},
			assert: func(t *testing.T, dp []metricdata.DataPoint[float64]) {
				t.Helper()

				require.Len(t, dp, 1)
				assertDataPointForCertificate(t, dp, s.ee4.Certificate)

				matching := dataPointsForCertificate(s.ee4.Certificate, dp)
				require.NotEmpty(t, matching)
				assert.Less(t, matching[0].Value, 0.0)
			},
		},
	} {
		s.Run(uc, func() {
			// GIVEN
			reader := metric.NewManualReader()
			provider := metric.NewMeterProvider(
				metric.WithResource(resource.Default()),
				metric.WithReader(reader),
			)

			reg, err := newRegistry(provider.Meter("keymaterial-registry-test"))
			s.Require().NoError(err)

			for _, event := range tc.events {
				reg.Notify(event)
			}

			var (
				rm metricdata.ResourceMetrics
				dp []metricdata.DataPoint[float64]
			)

			// WHEN
			s.Require().NoError(reader.Collect(s.T().Context(), &rm))

			// THEN
			if len(rm.ScopeMetrics) > 0 {
				s.Require().Len(rm.ScopeMetrics, 1)

				sm := rm.ScopeMetrics[0]
				s.Require().Len(sm.Metrics, 1)

				s.Equal("certificate.expiry", sm.Metrics[0].Name)
				s.Equal("s", sm.Metrics[0].Unit)
				s.Equal("Number of seconds until certificate expires", sm.Metrics[0].Description)

				data, ok := sm.Metrics[0].Data.(metricdata.Gauge[float64])
				s.Require().True(ok)

				dp = data.DataPoints
			}

			tc.assert(s.T(), dp)
		})
	}
}

func attributeValue(set attribute.Set, key attribute.Key) attribute.Value {
	if res, present := set.Value(key); present {
		return res
	}

	return attribute.Value{}
}

func dataPointsForCertificate(
	cert *x509.Certificate,
	points []metricdata.DataPoint[float64],
) []metricdata.DataPoint[float64] {
	matching := make([]metricdata.DataPoint[float64], 0, len(points))

	for _, dp := range points {
		val := attributeValue(dp.Attributes, certificateSubjectKey).AsString()
		if cert.Subject.String() == val {
			matching = append(matching, dp)
		}
	}

	return matching
}

func assertDataPointForCertificate(t *testing.T, points []metricdata.DataPoint[float64], cert *x509.Certificate) {
	t.Helper()

	data := dataPointsForCertificate(cert, points)
	require.NotEmpty(t, data)

	for _, dp := range data {
		assert.LessOrEqual(t, dp.Value-time.Until(cert.NotAfter).Seconds(), 1.0)
		assert.Equal(t, cert.Issuer.String(), attributeValue(dp.Attributes, certificateIssuerKey).AsString())
		assert.Equal(
			t,
			cert.SerialNumber.String(),
			attributeValue(dp.Attributes, certificateSerialNumberKey).AsString(),
		)
		assert.Equal(t, cert.Subject.String(), attributeValue(dp.Attributes, certificateSubjectKey).AsString())

		dnsNames := append([]string(nil), cert.DNSNames...)
		sort.Strings(dnsNames)
		assert.Equal(
			t,
			strings.Join(dnsNames, ","),
			attributeValue(dp.Attributes, certificateDNSNameKey).AsString(),
		)
	}
}
