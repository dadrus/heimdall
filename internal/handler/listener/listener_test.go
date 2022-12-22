package listener

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/testsupport"
)

func freePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}

	defer ln.Close()

	return ln.Addr().(*net.TCPAddr).Port, nil // nolint: forcetypeassert
}

func TestNewListener(t *testing.T) {
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

	pemBytes, err := testsupport.BuildPEM(
		testsupport.WithECDSAPrivateKey(privKey1, testsupport.WithPEMHeader("X-Key-ID", "key1")),
		testsupport.WithX509Certificate(cert),
		testsupport.WithECDSAPrivateKey(privKey2, testsupport.WithPEMHeader("X-Key-ID", "key2")),
	)
	require.NoError(t, err)

	pemFile, err := os.Create(filepath.Join(testDir, "keystore.pem"))
	require.NoError(t, err)

	_, err = pemFile.Write(pemBytes)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc          string
		network     string
		serviceConf config.ServiceConfig
		assert      func(t *testing.T, err error, ln net.Listener, port string)
	}{
		{
			uc:          "creation fails",
			network:     "foo",
			serviceConf: config.ServiceConfig{},
			assert: func(t *testing.T, err error, ln net.Listener, port string) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed creating listener")
			},
		},
		{
			uc:          "without TLS",
			network:     "tcp",
			serviceConf: config.ServiceConfig{Host: "127.0.0.1"},
			assert: func(t *testing.T, err error, ln net.Listener, port string) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ln)

				assert.Equal(t, "tcp", ln.Addr().Network())
				assert.Equal(t, "127.0.0.1:"+port, ln.Addr().String())
			},
		},
		{
			uc:      "fails due to not existent key store for TLS usage",
			network: "tcp",
			serviceConf: config.ServiceConfig{
				TLS: &config.TLS{KeyStore: "/no/such/file"},
			},
			assert: func(t *testing.T, err error, ln net.Listener, port string) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed loading")
			},
		},
		{
			uc:      "fails due to not existent key for the given key id for TLS usage",
			network: "tcp",
			serviceConf: config.ServiceConfig{
				TLS: &config.TLS{KeyStore: pemFile.Name(), KeyID: "foo", MinVersion: tls.VersionTLS12},
			},
			assert: func(t *testing.T, err error, ln net.Listener, port string) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no such key")
			},
		},
		{
			uc:      "fails due to not present certificates for the given key id",
			network: "tcp",
			serviceConf: config.ServiceConfig{
				TLS: &config.TLS{KeyStore: pemFile.Name(), KeyID: "key2", MinVersion: tls.VersionTLS12},
			},
			assert: func(t *testing.T, err error, ln net.Listener, port string) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no certificate present")
			},
		},
		{
			uc:      "successful with default key",
			network: "tcp",
			serviceConf: config.ServiceConfig{
				TLS: &config.TLS{KeyStore: pemFile.Name(), MinVersion: tls.VersionTLS12},
			},
			assert: func(t *testing.T, err error, ln net.Listener, port string) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ln)
				assert.Equal(t, "tcp", ln.Addr().Network())
				assert.Contains(t, ln.Addr().String(), port)
			},
		},
		{
			uc:      "successful with specified key id",
			network: "tcp",
			serviceConf: config.ServiceConfig{
				TLS: &config.TLS{KeyStore: pemFile.Name(), KeyID: "key1", MinVersion: tls.VersionTLS12},
			},
			assert: func(t *testing.T, err error, ln net.Listener, port string) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ln)
				assert.Equal(t, "tcp", ln.Addr().Network())
				assert.Contains(t, ln.Addr().String(), port)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			port, err := freePort()
			require.NoError(t, err)
			tc.serviceConf.Port = port

			// WHEN
			ln, err := New(tc.network, tc.serviceConf)

			// THEN
			defer func() {
				if ln != nil {
					ln.Close()
				}
			}()

			tc.assert(t, err, ln, strconv.Itoa(port))
		})
	}
}
