package tlsx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func newTestTLSSecret(t *testing.T, selector, keyID string) secrettypes.AsymmetricKeySecret {
	t.Helper()

	key := newECDSAKey(t)
	cert := newSelfSignedCertificate(t, key)

	return secrettypes.NewAsymmetricKeySecret("tls", selector, keyID, key, []*x509.Certificate{cert})
}

func newECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	return key
}

func newSelfSignedCertificate(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	cert, err := testsupport.NewCertificateBuilder(
		testsupport.WithValidity(time.Now(), 12*time.Hour),
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&key.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSelfSigned(),
		testsupport.WithSignaturePrivKey(key),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
	).Build()
	require.NoError(t, err)

	return cert
}
