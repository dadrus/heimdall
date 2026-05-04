package tlsx

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	keyregistry "github.com/dadrus/heimdall/internal/keyregistry/v2"
	keyregistrymocks "github.com/dadrus/heimdall/internal/keyregistry/v2/mocks"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewCertificateProvider(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setupMocks func(t *testing.T, sm *secretsmocks.ManagerMock, ko *keyregistrymocks.KeyObserverMock, cb *func(context.Context) error)
		assert     func(t *testing.T, err error, provider *certificateProvider, cb func(context.Context) error)
	}{
		"fails if subscribe fails": {
			setupMocks: func(t *testing.T, sm *secretsmocks.ManagerMock, ko *keyregistrymocks.KeyObserverMock, _ *func(context.Context) error) {
				t.Helper()

				secret := newTestTLSSecret(t, "server", "key1")
				ko.EXPECT().Notify(keyInfoMatching(secret)).Return()
				sm.EXPECT().
					ResolveSecret(context.Background(), secrets.InternalRef("tls", "server")).
					Return(secret, nil)
				sm.EXPECT().
					Subscribe(secrets.InternalRef("tls", "server"), mock.Anything).
					Return((func())(nil), errors.New("subscribe failed"))
			},
			assert: func(t *testing.T, err error, provider *certificateProvider, _ func(context.Context) error) {
				t.Helper()

				assert.Nil(t, provider)
				require.Error(t, err)
				require.ErrorContains(t, err, "subscribe failed")
			},
		},
		"reload callback updates certificate": {
			setupMocks: func(t *testing.T, sm *secretsmocks.ManagerMock, ko *keyregistrymocks.KeyObserverMock, cb *func(context.Context) error) {
				t.Helper()

				first := newTestTLSSecret(t, "server", "key1")
				second := newTestTLSSecret(t, "server", "key2")
				callNum := 0

				ko.EXPECT().Notify(keyInfoMatching(first)).Return()
				ko.EXPECT().Notify(keyInfoMatching(second)).Return()

				sm.EXPECT().
					ResolveSecret(context.Background(), secrets.InternalRef("tls", "server")).
					RunAndReturn(func(_ context.Context, _ secrets.Reference) (secrets.Secret, error) {
						callNum++
						if callNum == 1 {
							return first, nil
						}

						return second, nil
					})
				sm.EXPECT().
					Subscribe(secrets.InternalRef("tls", "server"), mock.Anything).
					Run(func(_ secrets.Reference, fn func(context.Context) error) {
						*cb = fn
					}).
					Return(func() {}, nil)
			},
			assert: func(t *testing.T, err error, provider *certificateProvider, cb func(context.Context) error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, provider)
				require.NotNil(t, cb)
				require.NoError(t, cb(context.Background()))

				cc := newCompatibilityCheckerMock(t)
				cc.EXPECT().SupportsCertificate(mock.Anything).Return(nil)

				cert, certErr := provider.certificate(cc)
				require.NoError(t, certErr)
				require.NotNil(t, cert)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			sm := secretsmocks.NewManagerMock(t)
			ko := keyregistrymocks.NewKeyObserverMock(t)

			var cb func(context.Context) error

			tc.setupMocks(t, sm, ko, &cb)

			provider, err := newCertificateProvider(
				context.Background(),
				secrets.InternalRef("tls", "server"),
				sm,
				ko,
			)

			tc.assert(t, err, provider, cb)
		})
	}
}

func TestCertificateProviderReload(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setupMocks func(t *testing.T, sm *secretsmocks.ManagerMock, ko *keyregistrymocks.KeyObserverMock)
		action     func(t *testing.T, provider *certificateProvider) error
		assert     func(t *testing.T, err error, provider *certificateProvider)
	}{
		"fails for non asymmetric secret": {
			setupMocks: func(t *testing.T, sm *secretsmocks.ManagerMock, _ *keyregistrymocks.KeyObserverMock) {
				t.Helper()

				sm.EXPECT().
					ResolveSecret(context.Background(), secrets.InternalRef("tls", "server")).
					Return(secrettypes.NewStringSecret("tls", "server", "nope"), nil)
			},
			action: func(t *testing.T, provider *certificateProvider) error {
				t.Helper()

				return provider.reload(context.Background())
			},
			assert: func(t *testing.T, err error, _ *certificateProvider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "not suitable for TLS")
			},
		},
		"fails if certificate chain is missing": {
			setupMocks: func(t *testing.T, sm *secretsmocks.ManagerMock, _ *keyregistrymocks.KeyObserverMock) {
				t.Helper()

				key := newECDSAKey(t)
				secret := secrettypes.NewAsymmetricKeySecret("tls", "server", "key1", key, nil)
				sm.EXPECT().
					ResolveSecret(context.Background(), secrets.InternalRef("tls", "server")).
					Return(secret, nil)
			},
			action: func(t *testing.T, provider *certificateProvider) error {
				t.Helper()

				return provider.reload(context.Background())
			},
			assert: func(t *testing.T, err error, _ *certificateProvider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "no certificate present")
			},
		},
		"keeps last known good certificate on reload failure": {
			setupMocks: func(t *testing.T, sm *secretsmocks.ManagerMock, ko *keyregistrymocks.KeyObserverMock) {
				t.Helper()

				first := newTestTLSSecret(t, "server", "key1")
				broken := secrettypes.NewStringSecret("tls", "server", "broken")
				callNum := 0

				ko.EXPECT().Notify(keyInfoMatching(first)).Return()
				sm.EXPECT().
					ResolveSecret(context.Background(), secrets.InternalRef("tls", "server")).
					RunAndReturn(func(_ context.Context, _ secrets.Reference) (secrets.Secret, error) {
						callNum++
						if callNum == 1 {
							return first, nil
						}

						return broken, nil
					})
			},
			action: func(t *testing.T, provider *certificateProvider) error {
				t.Helper()
				require.NoError(t, provider.reload(context.Background()))

				return provider.reload(context.Background())
			},
			assert: func(t *testing.T, err error, provider *certificateProvider) {
				t.Helper()

				require.Error(t, err)

				cc := newCompatibilityCheckerMock(t)
				cc.EXPECT().SupportsCertificate(mock.Anything).Return(nil)

				cert, certErr := provider.certificate(cc)
				require.NoError(t, certErr)
				require.NotNil(t, cert)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			sm := secretsmocks.NewManagerMock(t)
			ko := keyregistrymocks.NewKeyObserverMock(t)
			provider := &certificateProvider{
				reference: secrets.InternalRef("tls", "server"),
				sm:        sm,
				ko:        ko,
			}

			tc.setupMocks(t, sm, ko)
			err := tc.action(t, provider)

			tc.assert(t, err, provider)
		})
	}
}

func TestCertificateProviderCertificate(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, provider *certificateProvider, cc *compatibilityCheckerMock)
		assert func(t *testing.T, cert *tls.Certificate, err error)
	}{
		"fails if no certificate is loaded": {
			setup: func(t *testing.T, _ *certificateProvider, _ *compatibilityCheckerMock) { t.Helper() },
			assert: func(t *testing.T, cert *tls.Certificate, err error) {
				t.Helper()

				assert.Nil(t, cert)
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "no TLS certificate available")
			},
		},
		"returns compatibility checker error": {
			setup: func(t *testing.T, provider *certificateProvider, cc *compatibilityCheckerMock) {
				t.Helper()

				secret := newTestTLSSecret(t, "server", "key1")
				cert, err := toTLSCertificate(secret)
				require.NoError(t, err)

				provider.cert.Store(cert)
				cc.EXPECT().SupportsCertificate(cert).Return(errors.New("not supported"))
			},
			assert: func(t *testing.T, cert *tls.Certificate, err error) {
				t.Helper()

				assert.Nil(t, cert)
				require.Error(t, err)
				require.ErrorContains(t, err, "not supported")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			provider := &certificateProvider{}
			cc := newCompatibilityCheckerMock(t)

			tc.setup(t, provider, cc)
			cert, err := provider.certificate(cc)

			tc.assert(t, cert, err)
		})
	}
}

func TestToTLSCertificate(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T) secrettypes.AsymmetricKeySecret
		assert func(t *testing.T, cert *tls.Certificate, err error)
	}{
		"fails without certificate chain": {
			setup: func(t *testing.T) secrettypes.AsymmetricKeySecret {
				t.Helper()

				return secrettypes.NewAsymmetricKeySecret("tls", "server", "key1", newECDSAKey(t), nil)
			},
			assert: func(t *testing.T, cert *tls.Certificate, err error) {
				t.Helper()

				assert.Nil(t, cert)
				require.ErrorIs(t, err, errNoCertificatePresent)
			},
		},
		"creates tls certificate from full chain": {
			setup: func(t *testing.T) secrettypes.AsymmetricKeySecret {
				t.Helper()

				key := newECDSAKey(t)
				rootCA, err := testsupport.NewRootCA("Test Root CA", 24*time.Hour)
				require.NoError(t, err)

				leaf, err := rootCA.IssueCertificate(
					testsupport.WithSubject(pkix.Name{CommonName: "leaf"}),
					testsupport.WithValidity(time.Now(), 12*time.Hour),
					testsupport.WithSubjectPubKey(&key.PublicKey, x509.ECDSAWithSHA384),
					testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
				)
				require.NoError(t, err)

				return secrettypes.NewAsymmetricKeySecret(
					"tls", "server", "key1", key, []*x509.Certificate{leaf, rootCA.Certificate},
				)
			},
			assert: func(t *testing.T, cert *tls.Certificate, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cert)
				assert.NotNil(t, cert.PrivateKey)
				assert.NotNil(t, cert.Leaf)
				assert.Len(t, cert.Certificate, 2)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			secret := tc.setup(t)
			cert, err := toTLSCertificate(secret)

			tc.assert(t, cert, err)
		})
	}
}

func keyInfoMatching(secret secrets.AsymmetricKeySecret) any {
	return mock.MatchedBy(func(info keyregistry.KeyInfo) bool {
		return info.Key == secret && !info.Exportable
	})
}
