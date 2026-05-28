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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
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

	s.rootCA1, err = testsupport.NewRootCA("Test Root CA 1", time.Hour*24)
	s.Require().NoError(err)

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
	reg := newTestRegistry(s.T(), nil)

	reg.replaceSet(
		"test:keys",
		[]secrets.AsymmetricKeySecret{
			types.NewAsymmetricKeySecret(
				"kid-1",
				"kid-1",
				s.ee1.PrivKey,
				[]*x509.Certificate{s.ee1.Certificate},
			),
		},
	)

	allocs := testing.AllocsPerRun(1000, func() {
		_ = reg.Keys()
	})

	s.Equal(0, int(allocs))
}

func (s *RegistryTestSuite) TestDoNotify() {
	for uc, tc := range map[string]struct {
		ref       secrets.Reference
		secretSet []secrets.Secret
		assert    func(t *testing.T, reg *registry)
	}{
		"single certificate set published": {
			ref: secrets.Reference{Source: "pem", Selector: "jwt/signing/2026-05"},
			secretSet: []secrets.Secret{
				types.NewAsymmetricKeySecret(
					"kid-1",
					"kid-1",
					s.ee1.PrivKey,
					[]*x509.Certificate{s.ee1.Certificate},
				),
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				require.Len(t, reg.sets, 1)

				set := reg.sets["pem:jwt/signing"]
				require.Len(t, set, 1)
				assert.Contains(t, set, "kid-1")

				require.Len(t, reg.snapshot, 1)
				assert.Equal(t, "kid-1", reg.snapshot[0].KeyID)
				assert.Equal(t, s.ee1.Certificate.PublicKey, reg.snapshot[0].Key)
				assert.Len(t, reg.snapshot[0].Certificates, 1)
				assert.Equal(t, s.ee1.Certificate.Raw, reg.snapshot[0].Certificates[0].Raw)
				assert.Equal(t, string(jose.ES384), reg.snapshot[0].Algorithm)
				assert.Equal(t, "sig", reg.snapshot[0].Use)
			},
		},
		"multiple certificates with chains published": {
			ref: secrets.Reference{Source: "pem", Selector: "jwt/signing/2026-05"},
			secretSet: []secrets.Secret{
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

				require.Len(t, reg.sets, 1)

				set := reg.sets["pem:jwt/signing"]
				require.Len(t, set, 2)
				assert.Contains(t, set, "kid-1")
				assert.Contains(t, set, "kid-2")

				require.Len(t, reg.snapshot, 2)

				assert.Equal(t, "kid-1", reg.snapshot[0].KeyID)
				assert.Equal(t, s.ee1.Certificate.PublicKey, reg.snapshot[0].Key)
				require.Len(t, reg.snapshot[0].Certificates, 3)
				assert.Equal(t, s.ee1.Certificate.Raw, reg.snapshot[0].Certificates[0].Raw)
				assert.Equal(t, s.intCA1.Certificate.Raw, reg.snapshot[0].Certificates[1].Raw)
				assert.Equal(t, s.rootCA1.Certificate.Raw, reg.snapshot[0].Certificates[2].Raw)

				assert.Equal(t, "kid-2", reg.snapshot[1].KeyID)
				assert.Equal(t, s.ee2.Certificate.PublicKey, reg.snapshot[1].Key)
				require.Len(t, reg.snapshot[1].Certificates, 3)
				assert.Equal(t, s.ee2.Certificate.Raw, reg.snapshot[1].Certificates[0].Raw)
				assert.Equal(t, s.intCA1.Certificate.Raw, reg.snapshot[1].Certificates[1].Raw)
				assert.Equal(t, s.rootCA1.Certificate.Raw, reg.snapshot[1].Certificates[2].Raw)
			},
		},
		"single key without certificate chain published": {
			ref: secrets.Reference{Source: "pem", Selector: "jwt/signing/2026-05"},
			secretSet: []secrets.Secret{
				types.NewAsymmetricKeySecret(
					"kid-1",
					"kid-1",
					s.ee1.PrivKey,
					nil,
				),
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				require.Len(t, reg.sets, 1)

				set := reg.sets["pem:jwt/signing"]
				require.Len(t, set, 1)
				assert.Contains(t, set, "kid-1")

				secret := set["kid-1"]
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
		"non asymmetric secrets are ignored": {
			ref: secrets.Reference{Source: "pem", Selector: "jwt/signing/2026-05"},
			secretSet: []secrets.Secret{
				types.NewStringSecret("metadata", "ignored"),
				types.NewAsymmetricKeySecret(
					"kid-1",
					"kid-1",
					s.ee1.PrivKey,
					nil,
				),
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				require.Len(t, reg.sets, 1)

				set := reg.sets["pem:jwt/signing"]
				require.Len(t, set, 1)
				assert.Contains(t, set, "kid-1")

				require.Len(t, reg.snapshot, 1)
				assert.Equal(t, "kid-1", reg.snapshot[0].KeyID)
			},
		},
		"keys are exposed in deterministic key id order": {
			ref: secrets.Reference{Source: "pem", Selector: "jwt/signing/2026-05"},
			secretSet: []secrets.Secret{
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

				require.Len(t, reg.sets, 1)

				set := reg.sets["pem:jwt/signing"]
				require.Len(t, set, 3)
				assert.Contains(t, set, "kid-1")
				assert.Contains(t, set, "kid-2")
				assert.Contains(t, set, "kid-3")

				require.Len(t, reg.snapshot, 3)
				assert.Equal(t, "kid-1", reg.snapshot[0].KeyID)
				assert.Equal(t, "kid-2", reg.snapshot[1].KeyID)
				assert.Equal(t, "kid-3", reg.snapshot[2].KeyID)
			},
		},
		"single segment selector publishes provider root set": {
			ref: secrets.Reference{Source: "pem", Selector: "kid-1"},
			secretSet: []secrets.Secret{
				types.NewAsymmetricKeySecret(
					"kid-1",
					"kid-1",
					s.ee1.PrivKey,
					nil,
				),
			},
			assert: func(t *testing.T, reg *registry) {
				t.Helper()

				require.Len(t, reg.sets, 1)

				set := reg.sets["pem:"]
				require.Len(t, set, 1)
				assert.Contains(t, set, "kid-1")

				require.Len(t, reg.snapshot, 1)
				assert.Equal(t, "kid-1", reg.snapshot[0].KeyID)
			},
		},
	} {
		s.Run(uc, func() {
			parent := tc.ref.Parent()

			srf := secretsmocks.NewScopedResolverFactoryMock(s.T())
			scope := secretsmocks.NewScopedResolverMock(s.T())
			handle := secretsmocks.NewSecretSetHandleMock(s.T())

			srf.EXPECT().
				Create(publicationID(parent)).
				Return(scope)

			scope.EXPECT().
				SecretSet(mock.Anything, parent).
				Return(handle, nil)

			scope.EXPECT().
				AwaitReady(mock.Anything).
				Return(nil)

			handle.EXPECT().
				Get().
				Return(tc.secretSet, true)

			scope.EXPECT().
				Release()

			reg := newTestRegistry(s.T(), srf)

			reg.doNotify(context.Background(), tc.ref)

			tc.assert(s.T(), reg)
		})
	}
}

func (s *RegistryTestSuite) TestDoNotifyLogsIgnoredNonAsymmetricSecrets() {
	ref := secrets.Reference{Source: "pem", Selector: "jwt/signing/2026-05"}
	parent := ref.Parent()
	id := publicationID(parent)

	var logs bytes.Buffer

	srf := secretsmocks.NewScopedResolverFactoryMock(s.T())
	scope := secretsmocks.NewScopedResolverMock(s.T())
	handle := secretsmocks.NewSecretSetHandleMock(s.T())

	srf.EXPECT().
		Create(id).
		Return(scope)

	scope.EXPECT().
		SecretSet(mock.Anything, parent).
		Return(handle, nil)

	scope.EXPECT().
		AwaitReady(mock.Anything).
		Return(nil)

	handle.EXPECT().
		Get().
		Return([]secrets.Secret{
			types.NewStringSecret("metadata", "ignored"),
			types.NewAsymmetricKeySecret(
				"kid-1",
				"kid-1",
				s.ee1.PrivKey,
				nil,
			),
		}, true)

	scope.EXPECT().
		Release()

	reg := &registry{
		logger: zerolog.New(&logs),
		srf:    srf,
		sets:   make(map[string]map[string]secrets.AsymmetricKeySecret, 10),
	}

	reg.doNotify(context.Background(), ref)

	s.Require().Len(reg.sets, 1)
	s.Require().Len(reg.snapshot, 1)
	s.Equal("kid-1", reg.snapshot[0].KeyID)

	s.Contains(logs.String(), "Ignoring non-asymmetric key secret in verification key set")
	s.Contains(logs.String(), "metadata")
	s.Contains(logs.String(), string(types.SecretKindString))
}

func (s *RegistryTestSuite) TestDoNotifyReplacesExistingPublicationSet() {
	srf := secretsmocks.NewScopedResolverFactoryMock(s.T())

	reg := newTestRegistry(s.T(), srf)

	ref := secrets.Reference{Source: "pem", Selector: "jwt/signing/2026-05"}
	parent := ref.Parent()
	id := publicationID(parent)

	reg.replaceSet(
		id,
		[]secrets.AsymmetricKeySecret{
			types.NewAsymmetricKeySecret(
				"kid-1",
				"kid-1",
				s.ee1.PrivKey,
				[]*x509.Certificate{s.ee1.Certificate, s.intCA1.Certificate},
			),
		},
	)

	scope := secretsmocks.NewScopedResolverMock(s.T())
	handle := secretsmocks.NewSecretSetHandleMock(s.T())

	srf.EXPECT().
		Create(id).
		Return(scope)

	scope.EXPECT().
		SecretSet(mock.Anything, parent).
		Return(handle, nil)

	scope.EXPECT().
		AwaitReady(mock.Anything).
		Return(nil)

	handle.EXPECT().
		Get().
		Return([]secrets.Secret{
			types.NewAsymmetricKeySecret(
				"kid-1",
				"kid-1",
				s.ee3.PrivKey,
				[]*x509.Certificate{s.ee3.Certificate, s.intCA2.Certificate},
			),
		}, true)

	scope.EXPECT().
		Release()

	reg.doNotify(context.Background(), ref)

	s.Require().Len(reg.sets, 1)

	set := reg.sets[id]
	s.Require().Len(set, 1)
	s.Contains(set, "kid-1")

	secret := set["kid-1"]
	s.Equal(s.ee3.PrivKey.Public(), secret.PrivateKey().Public())
	s.Equal([]*x509.Certificate{s.ee3.Certificate, s.intCA2.Certificate}, secret.CertChain())

	s.Require().Len(reg.snapshot, 1)
	s.Equal("kid-1", reg.snapshot[0].KeyID)
	s.Equal(s.ee3.Certificate.PublicKey, reg.snapshot[0].Key)
	s.Require().Len(reg.snapshot[0].Certificates, 2)
	s.Equal(s.ee3.Certificate.Raw, reg.snapshot[0].Certificates[0].Raw)
	s.Equal(s.intCA2.Certificate.Raw, reg.snapshot[0].Certificates[1].Raw)
}

func (s *RegistryTestSuite) TestDoNotifyAggregatesDifferentPublicationSets() {
	srf := secretsmocks.NewScopedResolverFactoryMock(s.T())

	reg := newTestRegistry(s.T(), srf)

	ref1 := secrets.Reference{Source: "pem", Selector: "jwt/signing/2026-05"}
	parent1 := ref1.Parent()
	id1 := publicationID(parent1)

	scope1 := secretsmocks.NewScopedResolverMock(s.T())
	handle1 := secretsmocks.NewSecretSetHandleMock(s.T())

	srf.EXPECT().
		Create(id1).
		Return(scope1)

	scope1.EXPECT().
		SecretSet(mock.Anything, parent1).
		Return(handle1, nil)

	scope1.EXPECT().
		AwaitReady(mock.Anything).
		Return(nil)

	handle1.EXPECT().
		Get().
		Return([]secrets.Secret{
			types.NewAsymmetricKeySecret(
				"kid-1",
				"kid-1",
				s.ee1.PrivKey,
				nil,
			),
		}, true)

	scope1.EXPECT().
		Release()

	reg.doNotify(context.Background(), ref1)

	ref2 := secrets.Reference{Source: "pem", Selector: "hms/signing/2026-05"}
	parent2 := ref2.Parent()
	id2 := publicationID(parent2)

	scope2 := secretsmocks.NewScopedResolverMock(s.T())
	handle2 := secretsmocks.NewSecretSetHandleMock(s.T())

	srf.EXPECT().
		Create(id2).
		Return(scope2)

	scope2.EXPECT().
		SecretSet(mock.Anything, parent2).
		Return(handle2, nil)

	scope2.EXPECT().
		AwaitReady(mock.Anything).
		Return(nil)

	handle2.EXPECT().
		Get().
		Return([]secrets.Secret{
			types.NewAsymmetricKeySecret(
				"kid-2",
				"kid-2",
				s.ee2.PrivKey,
				nil,
			),
		}, true)

	scope2.EXPECT().
		Release()

	reg.doNotify(context.Background(), ref2)

	s.Require().Len(reg.sets, 2)
	s.Contains(reg.sets, id1)
	s.Contains(reg.sets, id2)

	s.Require().Len(reg.snapshot, 2)
	s.Equal("kid-1", reg.snapshot[0].KeyID)
	s.Equal("kid-2", reg.snapshot[1].KeyID)
}

func (s *RegistryTestSuite) TestDoNotifyFailsWithoutReplacingExistingSet() {
	for uc, tc := range map[string]struct {
		configure func(
			t *testing.T,
			ref secrets.Reference,
			srf *secretsmocks.ScopedResolverFactoryMock,
			scope *secretsmocks.ScopedResolverMock,
		)
		assertLogs string
	}{
		"creating secret set handle fails": {
			configure: func(
				t *testing.T,
				ref secrets.Reference,
				srf *secretsmocks.ScopedResolverFactoryMock,
				scope *secretsmocks.ScopedResolverMock,
			) {
				t.Helper()

				parent := ref.Parent()

				srf.EXPECT().
					Create(publicationID(parent)).
					Return(scope)

				scope.EXPECT().
					SecretSet(mock.Anything, parent).
					Return(nil, assert.AnError)

				scope.EXPECT().
					Release()
			},
			assertLogs: "Failed creating verification key set handle",
		},
		"await ready fails": {
			configure: func(
				t *testing.T,
				ref secrets.Reference,
				srf *secretsmocks.ScopedResolverFactoryMock,
				scope *secretsmocks.ScopedResolverMock,
			) {
				t.Helper()

				parent := ref.Parent()
				handle := secretsmocks.NewSecretSetHandleMock(t)

				srf.EXPECT().
					Create(publicationID(parent)).
					Return(scope)

				scope.EXPECT().
					SecretSet(mock.Anything, parent).
					Return(handle, nil)

				scope.EXPECT().
					AwaitReady(mock.Anything).
					Return(assert.AnError)

				scope.EXPECT().
					Release()
			},
			assertLogs: "Failed resolving verification key set",
		},
	} {
		s.Run(uc, func() {
			ref := secrets.Reference{Source: "pem", Selector: "jwt/signing/2026-05"}
			parent := ref.Parent()
			id := publicationID(parent)

			var logs bytes.Buffer

			srf := secretsmocks.NewScopedResolverFactoryMock(s.T())
			scope := secretsmocks.NewScopedResolverMock(s.T())

			reg := &registry{
				logger: zerolog.New(&logs),
				srf:    srf,
				sets:   make(map[string]map[string]secrets.AsymmetricKeySecret, 10),
			}

			reg.replaceSet(
				id,
				[]secrets.AsymmetricKeySecret{
					types.NewAsymmetricKeySecret(
						"kid-1",
						"kid-1",
						s.ee1.PrivKey,
						nil,
					),
				},
			)

			tc.configure(s.T(), ref, srf, scope)

			reg.doNotify(context.Background(), ref)

			s.Require().Len(reg.sets, 1)
			s.Contains(reg.sets, id)

			s.Require().Len(reg.snapshot, 1)
			s.Equal("kid-1", reg.snapshot[0].KeyID)

			s.Contains(logs.String(), tc.assertLogs)
		})
	}
}

func (s *RegistryTestSuite) TestNotifyPublishesVerificationSet() {
	synctest.Test(s.T(), func(t *testing.T) {
		ref := secrets.Reference{Source: "pem", Selector: "jwt/signing/2026-05"}
		parent := ref.Parent()
		id := publicationID(parent)

		srf := secretsmocks.NewScopedResolverFactoryMock(t)
		scope := secretsmocks.NewScopedResolverMock(t)
		handle := secretsmocks.NewSecretSetHandleMock(t)

		srf.EXPECT().
			Create(id).
			Return(scope)

		scope.EXPECT().
			SecretSet(mock.Anything, parent).
			Return(handle, nil)

		scope.EXPECT().
			AwaitReady(mock.Anything).
			Return(nil)

		handle.EXPECT().
			Get().
			Return([]secrets.Secret{
				types.NewAsymmetricKeySecret(
					"kid-1",
					"kid-1",
					s.ee1.PrivKey,
					nil,
				),
			}, true)

		scope.EXPECT().
			Release()

		reg := newTestRegistry(t, srf)

		reg.Notify(ref)

		synctest.Wait()

		require.Len(t, reg.sets, 1)

		set := reg.sets[id]
		require.Len(t, set, 1)
		assert.Contains(t, set, "kid-1")

		require.Len(t, reg.snapshot, 1)
		assert.Equal(t, "kid-1", reg.snapshot[0].KeyID)
	})
}

func (s *RegistryTestSuite) TestNotifyTimesOutVerificationSetPublication() {
	synctest.Test(s.T(), func(t *testing.T) {
		ref := secrets.Reference{Source: "pem", Selector: "jwt/signing/2026-05"}
		parent := ref.Parent()
		id := publicationID(parent)

		var logs bytes.Buffer

		srf := secretsmocks.NewScopedResolverFactoryMock(t)
		scope := secretsmocks.NewScopedResolverMock(t)
		handle := secretsmocks.NewSecretSetHandleMock(t)

		srf.EXPECT().
			Create(id).
			Return(scope)

		scope.EXPECT().
			SecretSet(mock.Anything, parent).
			Return(handle, nil)

		scope.EXPECT().
			AwaitReady(mock.Anything).
			RunAndReturn(func(ctx context.Context) error {
				<-ctx.Done()

				return ctx.Err()
			})

		scope.EXPECT().
			Release()

		reg := &registry{
			logger: zerolog.New(&logs),
			srf:    srf,
			sets:   make(map[string]map[string]secrets.AsymmetricKeySecret, 10),
		}

		reg.replaceSet(
			id,
			[]secrets.AsymmetricKeySecret{
				types.NewAsymmetricKeySecret(
					"kid-1",
					"kid-1",
					s.ee1.PrivKey,
					nil,
				),
			},
		)

		reg.Notify(ref)

		// Let the Notify goroutine start and block in AwaitReady.
		synctest.Wait()

		// Advance fake time beyond the Notify timeout.
		time.Sleep(15 * time.Second)

		// Let the goroutine observe ctx.Done(), log, release the scope, and exit.
		synctest.Wait()

		require.Len(t, reg.sets, 1)
		assert.Contains(t, reg.sets, id)

		require.Len(t, reg.snapshot, 1)
		assert.Equal(t, "kid-1", reg.snapshot[0].KeyID)

		assert.Contains(t, logs.String(), "Failed resolving verification key set")
		assert.Contains(t, logs.String(), context.DeadlineExceeded.Error())
	})
}

func newTestRegistry(t *testing.T, srf secrets.ScopedResolverFactory) *registry {
	t.Helper()

	if srf == nil {
		srf = secretsmocks.NewScopedResolverFactoryMock(t)
	}

	reg, err := newRegistry(zerolog.Nop(), srf)
	require.NoError(t, err)

	return reg.(*registry) //nolint:forcetypeassert
}
