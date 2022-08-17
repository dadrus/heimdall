package truststore

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

	"github.com/dadrus/heimdall/internal/testsupport"
)

func TestNewKeyStoreFromPEMBytes(t *testing.T) {
	// GIVEN
	// ROOT CAs
	rootCA1, err := testsupport.NewRootCA("Test Root CA 1", time.Hour*24)
	require.NoError(t, err)

	// INT CA
	intCA1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	intCA1Cert, err := rootCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test Int CA 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithIsCA(),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&intCA1PrivKey.PublicKey, x509.ECDSAWithSHA384))
	require.NoError(t, err)

	pemBytes, err := testsupport.BuildPEM(
		testsupport.WithX509Certificate(intCA1Cert),
		testsupport.WithX509Certificate(rootCA1.Certificate),
	)
	require.NoError(t, err)

	// WHEN
	ts, err := NewTrustStoreFromPEMBytes(pemBytes)

	// THEN
	require.NoError(t, err)

	assert.Len(t, ts, 2)
	assert.Equal(t, intCA1Cert, ts[0])
	assert.Equal(t, rootCA1.Certificate, ts[1])
}
