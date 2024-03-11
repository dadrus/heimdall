package tlsx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestTLSConfig(t *testing.T) {
	t.Parallel()

	testDir := t.TempDir()

	privKey1, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	privKey2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cert, err := testsupport.NewCertificateBuilder(testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&privKey1.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSelfSigned(),
		testsupport.WithSignaturePrivKey(privKey1)).
		Build()
	require.NoError(t, err)

	pemBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(privKey1, pemx.WithHeader("X-Key-ID", "key1")),
		pemx.WithX509Certificate(cert),
		pemx.WithECDSAPrivateKey(privKey2, pemx.WithHeader("X-Key-ID", "key2")),
	)
	require.NoError(t, err)

	pemFile, err := os.Create(filepath.Join(testDir, "keystore.pem"))
	require.NoError(t, err)

	_, err = pemFile.Write(pemBytes)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc         string
		conf       config.TLS
		serverAuth bool
		clientAuth bool
		assert     func(t *testing.T, err error, conf *tls.Config)
	}{
		{
			uc: "empty config",
			assert: func(t *testing.T, err error, conf *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, conf)

				assert.Empty(t, conf.Certificates)
				assert.Equal(t, uint16(tls.VersionTLS13), conf.MinVersion)
				assert.Len(t, conf.NextProtos, 2)
				assert.Contains(t, conf.NextProtos, "h2")
				assert.Contains(t, conf.NextProtos, "http/1.1")
			},
		},
		{
			uc:         "fails due to not existent key store for TLS usage",
			serverAuth: true,
			conf:       config.TLS{KeyStore: config.KeyStore{Path: "/no/such/file"}},
			assert: func(t *testing.T, err error, _ *tls.Config) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed loading")
			},
		},
		{
			uc:         "fails due to not existent key for the given key id for TLS usage",
			serverAuth: true,
			conf: config.TLS{
				KeyStore:   config.KeyStore{Path: pemFile.Name()},
				KeyID:      "foo",
				MinVersion: tls.VersionTLS12,
			},
			assert: func(t *testing.T, err error, _ *tls.Config) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no such key")
			},
		},
		{
			uc:         "fails due to not present certificates for the given key id",
			serverAuth: true,
			conf: config.TLS{
				KeyStore:   config.KeyStore{Path: pemFile.Name()},
				KeyID:      "key2",
				MinVersion: tls.VersionTLS12,
			},
			assert: func(t *testing.T, err error, _ *tls.Config) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no certificate present")
			},
		},
		{
			uc:         "successful with default key for TLS server auth",
			serverAuth: true,
			conf: config.TLS{
				KeyStore:   config.KeyStore{Path: pemFile.Name()},
				MinVersion: tls.VersionTLS12,
			},
			assert: func(t *testing.T, err error, conf *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, conf)

				assert.NotNil(t, conf.GetCertificate)
				assert.Equal(t, uint16(tls.VersionTLS12), conf.MinVersion)
				assert.Len(t, conf.NextProtos, 2)
				assert.Contains(t, conf.NextProtos, "h2")
				assert.Contains(t, conf.NextProtos, "http/1.1")
			},
		},
		{
			uc:         "successful with default key for TLS client auth",
			clientAuth: true,
			conf: config.TLS{
				KeyStore:   config.KeyStore{Path: pemFile.Name()},
				MinVersion: tls.VersionTLS12,
			},
			assert: func(t *testing.T, err error, conf *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, conf)

				assert.NotNil(t, conf.GetClientCertificate)
				assert.Equal(t, uint16(tls.VersionTLS12), conf.MinVersion)
				assert.Len(t, conf.NextProtos, 2)
				assert.Contains(t, conf.NextProtos, "h2")
				assert.Contains(t, conf.NextProtos, "http/1.1")
			},
		},
		{
			uc:         "successful with specified key id for TLS server auth",
			serverAuth: true,
			conf: config.TLS{
				KeyStore:   config.KeyStore{Path: pemFile.Name()},
				KeyID:      "key1",
				MinVersion: tls.VersionTLS12,
			},
			assert: func(t *testing.T, err error, conf *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, conf)

				assert.NotNil(t, conf.GetCertificate)
				assert.Equal(t, uint16(tls.VersionTLS12), conf.MinVersion)
				assert.Len(t, conf.NextProtos, 2)
				assert.Contains(t, conf.NextProtos, "h2")
				assert.Contains(t, conf.NextProtos, "http/1.1")
			},
		},
		{
			uc:         "successful with specified key id for TLS client auth",
			clientAuth: true,
			conf: config.TLS{
				KeyStore:   config.KeyStore{Path: pemFile.Name()},
				KeyID:      "key1",
				MinVersion: tls.VersionTLS12,
			},
			assert: func(t *testing.T, err error, conf *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, conf)

				assert.NotNil(t, conf.GetClientCertificate)
				assert.Equal(t, uint16(tls.VersionTLS12), conf.MinVersion)
				assert.Len(t, conf.NextProtos, 2)
				assert.Contains(t, conf.NextProtos, "h2")
				assert.Contains(t, conf.NextProtos, "http/1.1")
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// WHEN
			tlsCfg := tc.conf

			conf, err := ToTLSConfig(
				&tlsCfg,
				WithServerAuthentication(tc.serverAuth),
				WithClientAuthentication(tc.clientAuth),
			)

			// THEN
			tc.assert(t, err, conf)
		})
	}
}
