package redis

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewStandaloneCache(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cert, err := testsupport.NewCertificateBuilder(
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&key.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSignaturePrivKey(key),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
		testsupport.WithExtendedKeyUsage(x509.ExtKeyUsageServerAuth),
		testsupport.WithExtendedKeyUsage(x509.ExtKeyUsageClientAuth),
		testsupport.WithGeneratedSubjectKeyID(),
		testsupport.WithIPAddresses([]net.IP{net.ParseIP("127.0.0.1")}),
		testsupport.WithSelfSigned(),
	).Build()
	require.NoError(t, err)

	testDir := t.TempDir()

	pemBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(key),
		pemx.WithX509Certificate(cert),
	)
	require.NoError(t, err)

	pemFile, err := os.Create(filepath.Join(testDir, "keystore.pem"))
	require.NoError(t, err)

	_, err = pemFile.Write(pemBytes)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc     string
		config func(t *testing.T) []byte
		assert func(t *testing.T, err error, cch cache.Cache)
	}{
		{
			uc: "empty config",
			config: func(t *testing.T) []byte {
				t.Helper()

				return []byte(``)
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'address' is a required field")
			},
		},
		{
			uc: "empty address provided",
			config: func(t *testing.T) []byte {
				t.Helper()

				return []byte(`address: ""`)
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'address' is a required field")
			},
		},
		{
			uc: "config contains unsupported properties",
			config: func(t *testing.T) []byte {
				t.Helper()

				return []byte(`foo: bar`)
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding redis cache config")
			},
		},
		{
			uc: "not existing address provided",
			config: func(t *testing.T) []byte {
				t.Helper()

				return []byte(`address: "foo.local:12345"`)
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed creating redis client")
			},
		},
		{
			uc: "successful cache creation without TLS",
			config: func(t *testing.T) []byte {
				t.Helper()

				db := miniredis.RunT(t)

				return []byte(fmt.Sprintf(
					"{address: %s, client_cache: {disabled: true}, tls: {disabled: true}}",
					db.Addr(),
				))
			},
			assert: func(t *testing.T, err error, cch cache.Cache) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cch)

				err = cch.Set(context.TODO(), "foo", []byte("bar"), 1*time.Second)
				require.NoError(t, err)

				data, err := cch.Get(context.TODO(), "foo")
				require.NoError(t, err)

				require.Equal(t, []byte("bar"), data)
			},
		},
		{
			uc: "with failing TLS config",
			config: func(t *testing.T) []byte {
				t.Helper()

				return []byte(`{ tls: { key_store: { path: /does/not/exist.pem } }, address: "foo.local:12345"}`)
			},
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed creating tls configuration")
			},
		},
		{
			uc: "successful cache creation with TLS",
			config: func(t *testing.T) []byte {
				t.Helper()

				rootCertPool = x509.NewCertPool()
				rootCertPool.AddCert(cert)

				cfg := &tls.Config{
					Certificates: []tls.Certificate{
						{PrivateKey: key, Leaf: cert, Certificate: [][]byte{cert.Raw}},
					},
					MinVersion: tls.VersionTLS13,
				}

				db := miniredis.NewMiniRedis()
				err = db.StartTLS(cfg)
				require.NoError(t, err)

				t.Cleanup(db.Close)

				return []byte(fmt.Sprintf("{address: %s, client_cache: {disabled: true}}", db.Addr()))
			},
			assert: func(t *testing.T, err error, cch cache.Cache) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cch)

				err = cch.Set(context.TODO(), "foo", []byte("bar"), 1*time.Second)
				require.NoError(t, err)

				data, err := cch.Get(context.TODO(), "foo")
				require.NoError(t, err)

				require.Equal(t, []byte("bar"), data)
			},
		},
		{
			uc: "successful cache creation with mutual TLS",
			config: func(t *testing.T) []byte {
				t.Helper()

				rootCertPool = x509.NewCertPool()
				rootCertPool.AddCert(cert)

				cfg := &tls.Config{
					Certificates: []tls.Certificate{
						{PrivateKey: key, Leaf: cert, Certificate: [][]byte{cert.Raw}},
					},
					MinVersion: tls.VersionTLS13,
					ClientCAs:  rootCertPool,
					ClientAuth: tls.RequireAndVerifyClientCert,
				}

				db := miniredis.NewMiniRedis()
				err = db.StartTLS(cfg)
				require.NoError(t, err)

				t.Cleanup(db.Close)

				return []byte(fmt.Sprintf(
					"{address: %s, client_cache: {disabled: true}, tls: {key_store: {path: %s}}}",
					db.Addr(), pemFile.Name(),
				))
			},
			assert: func(t *testing.T, err error, cch cache.Cache) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cch)

				err = cch.Set(context.TODO(), "foo", []byte("bar"), 1*time.Second)
				require.NoError(t, err)

				data, err := cch.Get(context.TODO(), "foo")
				require.NoError(t, err)

				require.Equal(t, []byte("bar"), data)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config(t))
			require.NoError(t, err)

			// WHEN
			cch, err := NewStandaloneCache(conf, nil)
			if err == nil {
				defer cch.Stop(context.TODO())
			}

			// THEN
			tc.assert(t, err, cch)
		})
	}
}
