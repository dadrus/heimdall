package listener

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

func TestCreateNewListener(t *testing.T) {
	t.Parallel()

	testDir := t.TempDir()

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	privKeyPEMBytes, err := testsupport.BuildPEM(testsupport.WithECDSAPrivateKey(privKey))
	require.NoError(t, err)

	keyFile, err := os.Create(filepath.Join(testDir, "key.pem"))
	require.NoError(t, err)
	_, err = keyFile.Write(privKeyPEMBytes)
	require.NoError(t, err)

	cert, err := testsupport.NewCertificateBuilder(testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&privKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSelfSigned(),
		testsupport.WithSignaturePrivKey(privKey)).
		Build()
	require.NoError(t, err)

	certPEMBytes, err := testsupport.BuildPEM(testsupport.WithX509Certificate(cert))
	require.NoError(t, err)

	certFile, err := os.Create(filepath.Join(testDir, "cert.pem"))
	require.NoError(t, err)
	_, err = certFile.Write(certPEMBytes)
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
			uc:          "listener without TLS",
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
			uc:      "creation of listener with TLS fails",
			network: "tcp",
			serviceConf: config.ServiceConfig{
				TLS: &config.TLS{Key: "/no/such/key", Cert: "/no/such/cert"},
			},
			assert: func(t *testing.T, err error, ln net.Listener, port string) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed loading")
			},
		},
		{
			uc:      "listener with TLS",
			network: "tcp",
			serviceConf: config.ServiceConfig{
				TLS: &config.TLS{Key: keyFile.Name(), Cert: certFile.Name()},
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
