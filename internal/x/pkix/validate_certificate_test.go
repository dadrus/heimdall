package pkix

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestValidateCertificate(t *testing.T) {
	t.Parallel()

	ca, err := testsupport.NewRootCA("Test CA", time.Hour*24)
	require.NoError(t, err)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert, err := ca.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour*1),
		testsupport.WithSubjectPubKey(&privKey.PublicKey, x509.ECDSAWithSHA256),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
		testsupport.WithExtendedKeyUsage(x509.ExtKeyUsageServerAuth),
	)
	require.NoError(t, err)

	pemBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(privKey),
		pemx.WithX509Certificate(cert),
		pemx.WithX509Certificate(ca.Certificate),
	)
	require.NoError(t, err)

	testDir := t.TempDir()
	keyFile, err := os.Create(filepath.Join(testDir, "keys.pem"))
	require.NoError(t, err)

	_, err = keyFile.Write(pemBytes)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc     string
		option []ValidationOption
		err    bool
	}{
		{
			uc: "DNS name validation error",
			option: []ValidationOption{
				WithDNSName("foo.bar"),
				WithRootCACertificates([]*x509.Certificate{ca.Certificate}),
			},
			err: true,
		},
		{
			uc: "no chain for intermediate to default trust store",
			option: []ValidationOption{
				WithIntermediateCACertificates([]*x509.Certificate{ca.Certificate}),
			},
			err: true,
		},
		{
			uc: "no chain to system trust store",
			option: []ValidationOption{
				WithSystemTrustStore(),
			},
			err: true,
		},
		{
			uc: "validates with custom Root CA",
			option: []ValidationOption{
				WithRootCACertificates([]*x509.Certificate{ca.Certificate}),
			},
			err: false,
		},
		{
			uc: "validates for now (time)",
			option: []ValidationOption{
				WithCurrentTime(time.Now()),
				WithRootCACertificates([]*x509.Certificate{ca.Certificate}),
			},
			err: false,
		},
		{
			uc: "missing key usage",
			option: []ValidationOption{
				WithKeyUsage(x509.KeyUsageKeyAgreement),
				WithRootCACertificates([]*x509.Certificate{ca.Certificate}),
			},
			err: true,
		},
		{
			uc: "valid key usage",
			option: []ValidationOption{
				WithKeyUsage(x509.KeyUsageDigitalSignature),
				WithRootCACertificates([]*x509.Certificate{ca.Certificate}),
			},
			err: false,
		},
		{
			uc: "missing extended key usage",
			option: []ValidationOption{
				WithExtendedKeyUsage(x509.ExtKeyUsageEmailProtection),
				WithRootCACertificates([]*x509.Certificate{ca.Certificate}),
			},
			err: true,
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// WHEN
			err := ValidateCertificate(cert, tc.option...)

			// THEN
			if tc.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
