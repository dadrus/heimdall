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

package keystore_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

type CertChainTestSuite struct {
	suite.Suite

	rootCA1   *testsupport.CA
	rootCA2   *testsupport.CA
	crossCert *x509.Certificate

	intCA1 *testsupport.CA
	intCA2 *testsupport.CA
	intCA3 *testsupport.CA
	intCA4 *testsupport.CA

	ee1 *testsupport.EndEntity
	ee2 *testsupport.EndEntity
	ee3 *testsupport.EndEntity
	ee4 *testsupport.EndEntity
	ee5 *testsupport.EndEntity
}

func (suite *CertChainTestSuite) SetupSuite() {
	// set StartingNumber to one
	// Following hierarchies are built
	//                   ROOT CA 1 <- signed by -- CROSS CERT -----* ROOT CA 2
	//                   /       \                                    /
	//                  /         \                                  /
	//                 /           \                                /
	//          INT CA 1           INT CA 2                     INT CA 4
	//          /     \               /   \                       /
	//         /       \             /     \                     /
	//        /         \           /       \                   /
	//   EE CERT 1   EE CERT 2  EE CERT 3   INT CA 3       EE CERT 5
	//                                         |
	//                                         |
	//                                      EE CERT 4
	//
	// EE CERT 1 does not contain the required digital signature key usage
	// EE CERT 2 is not valid (timely)
	// EE CERT 3 is valid
	// EE CERT 4 is valid, but INT CA 3 is malformed
	// EE CERT 5 is valid, CROSS CERT should appear in the chain
	var err error

	// ROOT CAs
	suite.rootCA1, err = testsupport.NewRootCA("Test Root CA 1", time.Hour*24)
	suite.Require().NoError(err)

	suite.rootCA2, err = testsupport.NewRootCA("Test Root CA 2", time.Hour*24)
	suite.Require().NoError(err)

	// CROSS CERT
	suite.crossCert, err = suite.rootCA1.IssueCertificate(
		testsupport.WithSubject(suite.rootCA2.Certificate.Subject),
		testsupport.WithIsCA(),
		testsupport.WithValidity(suite.rootCA2.Certificate.NotBefore, time.Hour*24),
		testsupport.WithSubjectPubKey(suite.rootCA2.Certificate.PublicKey, x509.ECDSAWithSHA384),
	)
	suite.Require().NoError(err)

	// INT CAs
	intCA1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.Require().NoError(err)
	intCA1Cert, err := suite.rootCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test Int CA 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithIsCA(),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&intCA1PrivKey.PublicKey, x509.ECDSAWithSHA384))
	suite.Require().NoError(err)
	suite.intCA1 = testsupport.NewCA(intCA1PrivKey, intCA1Cert)

	intCA2PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.Require().NoError(err)
	intCA2Cert, err := suite.rootCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test Int CA 2",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithIsCA(),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&intCA2PrivKey.PublicKey, x509.ECDSAWithSHA384))
	suite.Require().NoError(err)
	suite.intCA2 = testsupport.NewCA(intCA2PrivKey, intCA2Cert)

	intCA3PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.Require().NoError(err)
	intCA3Cert, err := suite.intCA2.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test Int CA 3",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&intCA3PrivKey.PublicKey, x509.ECDSAWithSHA384))
	suite.Require().NoError(err)
	suite.intCA3 = testsupport.NewCA(intCA3PrivKey, intCA3Cert)

	intCA4PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.Require().NoError(err)
	intCA4Cert, err := suite.rootCA2.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test Int CA 4",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithIsCA(),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&intCA4PrivKey.PublicKey, x509.ECDSAWithSHA384))
	suite.Require().NoError(err)
	suite.intCA4 = testsupport.NewCA(intCA4PrivKey, intCA4Cert)

	// EE CERTS
	ee1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.Require().NoError(err)
	ee1cert, err := suite.intCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&ee1PrivKey.PublicKey, x509.ECDSAWithSHA384))
	suite.Require().NoError(err)
	suite.ee1 = &testsupport.EndEntity{Certificate: ee1cert, PrivKey: ee1PrivKey}

	ee2PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.Require().NoError(err)
	ee2cert, err := suite.intCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 2",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now().Add(-time.Hour*24), time.Hour*1),
		testsupport.WithSubjectPubKey(&ee2PrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
	suite.Require().NoError(err)
	suite.ee2 = &testsupport.EndEntity{Certificate: ee2cert, PrivKey: ee2PrivKey}

	ee3PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.Require().NoError(err)
	ee3cert, err := suite.intCA2.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 3",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour*1),
		testsupport.WithSubjectPubKey(&ee3PrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
	suite.Require().NoError(err)
	suite.ee3 = &testsupport.EndEntity{Certificate: ee3cert, PrivKey: ee3PrivKey}

	ee4PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.Require().NoError(err)
	ee4cert, err := suite.intCA3.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 4",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour*1),
		testsupport.WithSubjectPubKey(&ee4PrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
	suite.Require().NoError(err)
	suite.ee4 = &testsupport.EndEntity{Certificate: ee4cert, PrivKey: ee4PrivKey}

	ee5PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.Require().NoError(err)
	ee5cert, err := suite.intCA4.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 5",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour*1),
		testsupport.WithSubjectPubKey(&ee5PrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
	suite.Require().NoError(err)
	suite.ee5 = &testsupport.EndEntity{Certificate: ee5cert, PrivKey: ee5PrivKey}
}

func TestCertChainTestSuite(t *testing.T) {
	suite.Run(t, new(CertChainTestSuite))
}

func (suite *CertChainTestSuite) TestFindChain() {
	for _, tc := range []struct {
		uc       string
		eeCert   *x509.Certificate
		certPool []*x509.Certificate
		assert   func(t *testing.T, chain []*x509.Certificate)
	}{
		{
			uc:     "can find chain",
			eeCert: suite.ee1.Certificate,
			certPool: []*x509.Certificate{
				suite.intCA2.Certificate, suite.rootCA1.Certificate, suite.intCA1.Certificate,
				suite.ee1.Certificate, suite.rootCA2.Certificate,
			},
			assert: func(t *testing.T, chain []*x509.Certificate) {
				t.Helper()

				require.Len(t, chain, 3)
				assert.Equal(t, suite.ee1.Certificate, chain[0])
				assert.Equal(t, suite.intCA1.Certificate, chain[1])
				assert.Equal(t, suite.rootCA1.Certificate, chain[2])
			},
		},
		{
			uc:     "can find chain, but is incomplete due to missing intermediate CA",
			eeCert: suite.ee1.Certificate,
			certPool: []*x509.Certificate{
				suite.intCA2.Certificate, suite.rootCA1.Certificate,
				suite.ee1.Certificate, suite.rootCA2.Certificate,
			},
			assert: func(t *testing.T, chain []*x509.Certificate) {
				t.Helper()

				require.Len(t, chain, 1)
				assert.Equal(t, suite.ee1.Certificate, chain[0])
			},
		},
		{
			uc:     "can not find chain due to missing ee cert",
			eeCert: suite.ee1.Certificate,
			certPool: []*x509.Certificate{
				suite.intCA2.Certificate, suite.rootCA1.Certificate,
				suite.intCA1.Certificate, suite.rootCA2.Certificate,
			},
			assert: func(t *testing.T, chain []*x509.Certificate) {
				t.Helper()

				require.Empty(t, chain)
			},
		},
		{
			uc:     "can find chain, chain includes cross cert",
			eeCert: suite.ee5.Certificate,
			certPool: []*x509.Certificate{
				suite.intCA4.Certificate, suite.rootCA1.Certificate, suite.intCA1.Certificate,
				suite.ee5.Certificate, suite.rootCA2.Certificate, suite.crossCert,
			},
			assert: func(t *testing.T, chain []*x509.Certificate) {
				t.Helper()

				require.Len(t, chain, 5)
				assert.Equal(t, suite.ee5.Certificate, chain[0])
				assert.Equal(t, suite.intCA4.Certificate, chain[1])
				assert.Equal(t, suite.rootCA2.Certificate, chain[2])
				assert.Equal(t, suite.crossCert, chain[3])
				assert.Equal(t, suite.rootCA1.Certificate, chain[4])
			},
		},
	} {
		suite.T().Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN

			// WHEN
			chain := keystore.FindChain(tc.eeCert.PublicKey, tc.certPool)

			// THEN
			tc.assert(t, chain)
		})
	}
}

func (suite *CertChainTestSuite) TestValidateChain() {
	for _, tc := range []struct {
		uc       string
		eeCert   *x509.Certificate
		certPool []*x509.Certificate
		assert   func(t *testing.T, err error)
	}{
		{
			uc:     "chain is invalid due timely invalid ee certificate",
			eeCert: suite.ee2.Certificate,
			certPool: []*x509.Certificate{
				suite.intCA2.Certificate, suite.rootCA1.Certificate, suite.intCA1.Certificate,
				suite.ee2.Certificate, suite.rootCA2.Certificate,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "certificate has expired or is not yet valid")
			},
		},
		{
			uc:     "chain is valid",
			eeCert: suite.ee3.Certificate,
			certPool: []*x509.Certificate{
				suite.intCA2.Certificate, suite.rootCA1.Certificate, suite.intCA1.Certificate,
				suite.ee3.Certificate, suite.rootCA2.Certificate,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:     "chain is invalid due to malformed CA",
			eeCert: suite.ee4.Certificate,
			certPool: []*x509.Certificate{
				suite.intCA2.Certificate, suite.rootCA1.Certificate, suite.intCA3.Certificate,
				suite.ee4.Certificate, suite.rootCA2.Certificate,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "parent certificate cannot sign")
			},
		},
		{
			uc:     "chain with cross cert is valid",
			eeCert: suite.ee5.Certificate,
			certPool: []*x509.Certificate{
				suite.intCA4.Certificate, suite.rootCA1.Certificate, suite.intCA1.Certificate,
				suite.ee5.Certificate, suite.rootCA2.Certificate, suite.crossCert,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		suite.T().Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			chain := keystore.FindChain(tc.eeCert.PublicKey, tc.certPool)

			// WHEN
			err := keystore.ValidateChain(chain)

			// THEN
			tc.assert(t, err)
		})
	}
}
