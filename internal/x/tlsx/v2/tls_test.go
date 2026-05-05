package tlsx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestToTLSConfig(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

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

	secret := types.NewAsymmetricKeySecret("tls", "server", "key1", key, []*x509.Certificate{cert})

	for uc, tc := range map[string]struct {
		conf       config.TLS
		serverAuth bool
		clientAuth bool
		setupMocks func(t *testing.T, sm *secretsmocks.ManagerMock)
		assert     func(t *testing.T, err error, cfg *tls.Config)
	}{
		"empty config": {
			assert: func(t *testing.T, err error, cfg *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cfg)

				assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
				assert.Nil(t, cfg.GetCertificate)
				assert.Nil(t, cfg.GetClientCertificate)
				assert.Equal(t, []string{"h2", "http/1.1"}, cfg.NextProtos)
				assert.Empty(t, cfg.CipherSuites)
			},
		},
		"fails if secret resolution fails": {
			serverAuth: true,
			conf: config.TLS{
				Secret: config.Secret{Source: "tls", Selector: "server"},
			},
			setupMocks: func(t *testing.T, sm *secretsmocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().
					ResolveSecret(mock.Anything, secrets.InternalRef("tls", "server")).
					Return(nil, errors.New("boom"))
			},
			assert: func(t *testing.T, err error, cfg *tls.Config) {
				t.Helper()

				assert.Nil(t, cfg)
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed resolving secret")
			},
		},
		"successful with server auth": {
			serverAuth: true,
			conf: config.TLS{
				Secret:     config.Secret{Source: "tls", Selector: "server"},
				MinVersion: tls.VersionTLS12,
			},
			setupMocks: func(t *testing.T, sm *secretsmocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().
					ResolveSecret(mock.Anything, secrets.InternalRef("tls", "server")).
					Return(secret, nil)
				sm.EXPECT().
					Subscribe(secrets.InternalRef("tls", "server"), mock.Anything).
					Return(func() {}, nil)
			},
			assert: func(t *testing.T, err error, cfg *tls.Config) {
				t.Helper()

				cc := newCompatibilityCheckerMock(t)
				cc.EXPECT().SupportsCertificate(cert).Return(nil)

				require.NoError(t, err)
				require.NotNil(t, cfg)

				assert.NotNil(t, cfg.GetCertificate)
				require.NoError(t, err)
				assert.Nil(t, cfg.GetClientCertificate)
				assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
				assert.NotEmpty(t, cfg.CipherSuites)
				assert.Equal(t, []string{"h2", "http/1.1"}, cfg.NextProtos)
			},
		},
		"successful with client auth": {
			clientAuth: true,
			conf: config.TLS{
				Secret: config.Secret{Source: "tls", Selector: "client"},
			},
			setupMocks: func(t *testing.T, sm *secretsmocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().
					ResolveSecret(mock.Anything, secrets.InternalRef("tls", "client")).
					Return(secret, nil)
				sm.EXPECT().
					Subscribe(secrets.InternalRef("tls", "client"), mock.Anything).
					Return(func() {}, nil)
			},
			assert: func(t *testing.T, err error, cfg *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cfg)

				assert.Nil(t, cfg.GetCertificate)
				assert.NotNil(t, cfg.GetClientCertificate)
				assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
				assert.Empty(t, cfg.CipherSuites)
				assert.Equal(t, []string{"h2", "http/1.1"}, cfg.NextProtos)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			sm := secretsmocks.NewManagerMock(t)
			opts := []Option{WithSecretsManager(sm)}
			setupMocks := x.IfThenElse(
				tc.setupMocks != nil,
				tc.setupMocks,
				func(t *testing.T, _ *secretsmocks.ManagerMock) { t.Helper() },
			)

			if tc.serverAuth {
				opts = append(opts, WithServerAuthentication(true))
			}

			if tc.clientAuth {
				opts = append(opts, WithClientAuthentication(true))
			}

			setupMocks(t, sm)

			cfg, err := ToTLSConfig(t.Context(), &tc.conf, opts...)

			tc.assert(t, err, cfg)
		})
	}
}
