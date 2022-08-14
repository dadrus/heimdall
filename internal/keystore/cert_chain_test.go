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
)

type EndEntity struct {
	cert    *x509.Certificate
	privKey any
}

type CertChainTestSuite struct {
	suite.Suite

	rootCA1   *CA
	rootCA2   *CA
	crossCert *x509.Certificate

	intCA1 *CA
	intCA2 *CA
	intCA3 *CA
	intCA4 *CA

	ee1 *EndEntity
	ee2 *EndEntity
	ee3 *EndEntity
	ee4 *EndEntity
	ee5 *EndEntity
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
	suite.rootCA1, err = NewRootCA("Test Root CA 1", time.Hour*24)
	suite.NoError(err)

	suite.rootCA2, err = NewRootCA("Test Root CA 2", time.Hour*24)
	suite.NoError(err)

	// CROSS CERT
	suite.crossCert, err = suite.rootCA1.IssueCertificate(
		WithSubject(suite.rootCA2.cert.Subject),
		WithIsCA(),
		WithValidity(suite.rootCA2.cert.NotBefore, time.Hour*24),
		WithSubjectPubKey(suite.rootCA2.cert.PublicKey, x509.ECDSAWithSHA384),
	)
	suite.NoError(err)

	// INT CAs
	intCA1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.NoError(err)
	intCA1Cert, err := suite.rootCA1.IssueCertificate(
		WithSubject(pkix.Name{
			CommonName:   "Test Int CA 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		WithIsCA(),
		WithValidity(time.Now(), time.Hour*24),
		WithSubjectPubKey(&intCA1PrivKey.PublicKey, x509.ECDSAWithSHA384))
	suite.NoError(err)
	suite.intCA1 = NewCA(intCA1PrivKey, intCA1Cert)

	intCA2PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.NoError(err)
	intCA2Cert, err := suite.rootCA1.IssueCertificate(
		WithSubject(pkix.Name{
			CommonName:   "Test Int CA 2",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		WithIsCA(),
		WithValidity(time.Now(), time.Hour*24),
		WithSubjectPubKey(&intCA2PrivKey.PublicKey, x509.ECDSAWithSHA384))
	suite.NoError(err)
	suite.intCA2 = NewCA(intCA2PrivKey, intCA2Cert)

	intCA3PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.NoError(err)
	intCA3Cert, err := suite.intCA2.IssueCertificate(
		WithSubject(pkix.Name{
			CommonName:   "Test Int CA 3",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		WithKeyUsage(x509.KeyUsageDigitalSignature),
		WithValidity(time.Now(), time.Hour*24),
		WithSubjectPubKey(&intCA3PrivKey.PublicKey, x509.ECDSAWithSHA384))
	suite.NoError(err)
	suite.intCA3 = NewCA(intCA3PrivKey, intCA3Cert)

	intCA4PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.NoError(err)
	intCA4Cert, err := suite.rootCA2.IssueCertificate(
		WithSubject(pkix.Name{
			CommonName:   "Test Int CA 4",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		WithIsCA(),
		WithValidity(time.Now(), time.Hour*24),
		WithSubjectPubKey(&intCA4PrivKey.PublicKey, x509.ECDSAWithSHA384))
	suite.NoError(err)
	suite.intCA4 = NewCA(intCA4PrivKey, intCA4Cert)

	// EE CERTS
	ee1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(suite.T(), err)
	ee1cert, err := suite.intCA1.IssueCertificate(
		WithSubject(pkix.Name{
			CommonName:   "Test EE 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		WithValidity(time.Now(), time.Hour*24),
		WithSubjectPubKey(&ee1PrivKey.PublicKey, x509.ECDSAWithSHA384))
	suite.NoError(err)
	suite.ee1 = &EndEntity{cert: ee1cert, privKey: ee1PrivKey}

	ee2PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.NoError(err)
	ee2cert, err := suite.intCA1.IssueCertificate(
		WithSubject(pkix.Name{
			CommonName:   "Test EE 2",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		WithValidity(time.Now().Add(-time.Hour*24), time.Hour*1),
		WithSubjectPubKey(&ee2PrivKey.PublicKey, x509.ECDSAWithSHA384),
		WithKeyUsage(x509.KeyUsageDigitalSignature))
	suite.NoError(err)
	suite.ee2 = &EndEntity{cert: ee2cert, privKey: ee2PrivKey}

	ee3PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.NoError(err)
	ee3cert, err := suite.intCA2.IssueCertificate(
		WithSubject(pkix.Name{
			CommonName:   "Test EE 3",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		WithValidity(time.Now(), time.Hour*1),
		WithSubjectPubKey(&ee3PrivKey.PublicKey, x509.ECDSAWithSHA384),
		WithKeyUsage(x509.KeyUsageDigitalSignature))
	suite.NoError(err)
	suite.ee3 = &EndEntity{cert: ee3cert, privKey: ee3PrivKey}

	ee4PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.NoError(err)
	ee4cert, err := suite.intCA3.IssueCertificate(
		WithSubject(pkix.Name{
			CommonName:   "Test EE 4",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		WithValidity(time.Now(), time.Hour*1),
		WithSubjectPubKey(&ee4PrivKey.PublicKey, x509.ECDSAWithSHA384),
		WithKeyUsage(x509.KeyUsageDigitalSignature))
	suite.NoError(err)
	suite.ee4 = &EndEntity{cert: ee4cert, privKey: ee4PrivKey}

	ee5PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.NoError(err)
	ee5cert, err := suite.intCA4.IssueCertificate(
		WithSubject(pkix.Name{
			CommonName:   "Test EE 5",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		WithValidity(time.Now(), time.Hour*1),
		WithSubjectPubKey(&ee5PrivKey.PublicKey, x509.ECDSAWithSHA384),
		WithKeyUsage(x509.KeyUsageDigitalSignature))
	suite.NoError(err)
	suite.ee5 = &EndEntity{cert: ee5cert, privKey: ee5PrivKey}
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
			eeCert: suite.ee1.cert,
			certPool: []*x509.Certificate{
				suite.intCA2.cert, suite.rootCA1.cert, suite.intCA1.cert, suite.ee1.cert, suite.rootCA2.cert,
			},
			assert: func(t *testing.T, chain []*x509.Certificate) {
				t.Helper()

				require.Len(t, chain, 3)
				assert.Equal(t, suite.ee1.cert, chain[0])
				assert.Equal(t, suite.intCA1.cert, chain[1])
				assert.Equal(t, suite.rootCA1.cert, chain[2])
			},
		},
		{
			uc:     "can find chain, but is is incomplete due to missing intermediate CA",
			eeCert: suite.ee1.cert,
			certPool: []*x509.Certificate{
				suite.intCA2.cert, suite.rootCA1.cert, suite.ee1.cert, suite.rootCA2.cert,
			},
			assert: func(t *testing.T, chain []*x509.Certificate) {
				t.Helper()

				require.Len(t, chain, 1)
				assert.Equal(t, suite.ee1.cert, chain[0])
			},
		},
		{
			uc:     "can not find chain due to missing ee cert",
			eeCert: suite.ee1.cert,
			certPool: []*x509.Certificate{
				suite.intCA2.cert, suite.rootCA1.cert, suite.intCA1.cert, suite.rootCA2.cert,
			},
			assert: func(t *testing.T, chain []*x509.Certificate) {
				t.Helper()

				require.Empty(t, chain)
			},
		},
		{
			uc:     "can find chain, chain includes cross cert",
			eeCert: suite.ee5.cert,
			certPool: []*x509.Certificate{
				suite.intCA4.cert, suite.rootCA1.cert, suite.intCA1.cert,
				suite.ee5.cert, suite.rootCA2.cert, suite.crossCert,
			},
			assert: func(t *testing.T, chain []*x509.Certificate) {
				t.Helper()

				require.Len(t, chain, 5)
				assert.Equal(t, suite.ee5.cert, chain[0])
				assert.Equal(t, suite.intCA4.cert, chain[1])
				assert.Equal(t, suite.rootCA2.cert, chain[2])
				assert.Equal(t, suite.crossCert, chain[3])
				assert.Equal(t, suite.rootCA1.cert, chain[4])
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
			uc:     "chain is invalid due to missing required key usage",
			eeCert: suite.ee1.cert,
			certPool: []*x509.Certificate{
				suite.intCA2.cert, suite.rootCA1.cert, suite.intCA1.cert, suite.ee1.cert, suite.rootCA2.cert,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "cannot be used for digital signature")
			},
		},
		{
			uc:     "chain is invalid due timely invalid ee certificate",
			eeCert: suite.ee2.cert,
			certPool: []*x509.Certificate{
				suite.intCA2.cert, suite.rootCA1.cert, suite.intCA1.cert, suite.ee2.cert, suite.rootCA2.cert,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "certificate has expired or is not yet valid")
			},
		},
		{
			uc:     "chain is valid",
			eeCert: suite.ee3.cert,
			certPool: []*x509.Certificate{
				suite.intCA2.cert, suite.rootCA1.cert, suite.intCA1.cert, suite.ee3.cert, suite.rootCA2.cert,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:     "chain is invalid due to malformed CA",
			eeCert: suite.ee4.cert,
			certPool: []*x509.Certificate{
				suite.intCA2.cert, suite.rootCA1.cert, suite.intCA3.cert, suite.ee4.cert, suite.rootCA2.cert,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "parent certificate cannot sign")
			},
		},
		{
			uc:     "chain with cross cert is valid",
			eeCert: suite.ee5.cert,
			certPool: []*x509.Certificate{
				suite.intCA4.cert, suite.rootCA1.cert, suite.intCA1.cert,
				suite.ee5.cert, suite.rootCA2.cert, suite.crossCert,
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
