package tlsx

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
)

func TestToTLSConfig(t *testing.T) {
	t.Parallel()

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
		"fails if server auth is required without secret source": {
			serverAuth: true,
			assert: func(t *testing.T, err error, cfg *tls.Config) {
				t.Helper()

				assert.Nil(t, cfg)
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "no tls secret source specified")
			},
		},
		"fails if tls auth is required without secrets manager": {
			serverAuth: true,
			conf: config.TLS{
				Secret: config.Secret{Source: "tls", Selector: "server"},
			},
			assert: func(t *testing.T, err error, cfg *tls.Config) {
				t.Helper()

				assert.Nil(t, cfg)
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "no secrets manager provided")
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
					ResolveSecret(context.Background(), secrets.InternalRef("tls", "server")).
					Return(nil, errors.New("boom"))
			},
			assert: func(t *testing.T, err error, cfg *tls.Config) {
				t.Helper()

				assert.Nil(t, cfg)
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed resolving TLS secret")
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

				secret := newTestTLSSecret(t, "server", "server-key")
				sm.EXPECT().
					ResolveSecret(context.Background(), secrets.InternalRef("tls", "server")).
					Return(secret, nil)
				sm.EXPECT().
					Subscribe(secrets.InternalRef("tls", "server"), mock.Anything).
					Return(func() {}, nil)
			},
			assert: func(t *testing.T, err error, cfg *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cfg)

				assert.NotNil(t, cfg.GetCertificate)
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

				secret := newTestTLSSecret(t, "client", "client-key")
				sm.EXPECT().
					ResolveSecret(context.Background(), secrets.InternalRef("tls", "client")).
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
			t.Parallel()

			var opts []Option
			if tc.serverAuth {
				opts = append(opts, WithServerAuthentication(true))
			}

			if tc.clientAuth {
				opts = append(opts, WithClientAuthentication(true))
			}

			if tc.setupMocks != nil {
				sm := secretsmocks.NewManagerMock(t)
				tc.setupMocks(t, sm)
				opts = append(opts, WithSecretsManager(sm))
			}

			cfg, err := ToTLSConfig(context.Background(), &tc.conf, opts...)

			tc.assert(t, err, cfg)
		})
	}
}
