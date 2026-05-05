package tlsx

import (
	"context"
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

	"github.com/dadrus/heimdall/internal/keyregistry/v2"
	keyregistrymocks "github.com/dadrus/heimdall/internal/keyregistry/v2/mocks"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewCertificateProvider(t *testing.T) {
	t.Parallel()

	key1, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cert1, err := testsupport.NewCertificateBuilder(
		testsupport.WithValidity(time.Now(), 12*time.Hour),
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&key1.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSelfSigned(),
		testsupport.WithSignaturePrivKey(key1),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
	).Build()
	require.NoError(t, err)

	key2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cert2, err := testsupport.NewCertificateBuilder(
		testsupport.WithValidity(time.Now(), 12*time.Hour),
		testsupport.WithSerialNumber(big.NewInt(2)),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert 2",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&key2.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSelfSigned(),
		testsupport.WithSignaturePrivKey(key2),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
	).Build()
	require.NoError(t, err)

	first := types.NewAsymmetricKeySecret("tls", "server", "key1", key1, []*x509.Certificate{cert1})
	second := types.NewAsymmetricKeySecret("tls", "server", "key2", key2, []*x509.Certificate{cert2})

	for uc, tc := range map[string]struct {
		reference  secrets.Reference
		setupMocks func(t *testing.T, sm *secretsmocks.ManagerMock, ko *keyregistrymocks.KeyObserverMock, cb *func(context.Context) error)
		assert     func(t *testing.T, err error, provider *certificateProvider, cb func(context.Context) error)
	}{
		"fails if reload fails": {
			setupMocks: func(t *testing.T, sm *secretsmocks.ManagerMock, ko *keyregistrymocks.KeyObserverMock, cb *func(context.Context) error) {
				t.Helper()

				sm.EXPECT().
					ResolveSecret(mock.Anything, mock.Anything).
					Return(nil, errors.New("resolve failed"))
			},
			assert: func(t *testing.T, err error, _ *certificateProvider, _ func(context.Context) error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "resolve failed")
			},
		},
		"fails if subscribe fails": {
			reference: secrets.InternalRef("tls", "server"),
			setupMocks: func(t *testing.T, sm *secretsmocks.ManagerMock, ko *keyregistrymocks.KeyObserverMock, _ *func(context.Context) error) {
				t.Helper()

				ko.EXPECT().Notify(keyInfoMatching(first)).Return()
				sm.EXPECT().
					ResolveSecret(mock.Anything, secrets.InternalRef("tls", "server")).
					Return(first, nil)
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
			reference: secrets.InternalRef("tls", "server"),
			setupMocks: func(t *testing.T, sm *secretsmocks.ManagerMock, ko *keyregistrymocks.KeyObserverMock, cb *func(context.Context) error) {
				t.Helper()

				callNum := 0

				ko.EXPECT().Notify(keyInfoMatching(first)).Return()
				ko.EXPECT().Notify(keyInfoMatching(second)).Return()

				sm.EXPECT().
					ResolveSecret(mock.Anything, secrets.InternalRef("tls", "server")).
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
				require.NoError(t, cb(t.Context()))

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

			provider, err := newCertificateProvider(t.Context(), tc.reference, sm, ko)

			tc.assert(t, err, provider, cb)
		})
	}
}

func TestCertificateProviderReload(t *testing.T) {
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

	valid := types.NewAsymmetricKeySecret("tls", "server", "key1", key, []*x509.Certificate{cert})
	invalid := types.NewAsymmetricKeySecret("tls", "server", "key1", key, nil)
	wrongType := types.NewStringSecret("tls", "server", "broken")

	for uc, tc := range map[string]struct {
		setupMocks func(t *testing.T, sm *secretsmocks.ManagerMock, ko *keyregistrymocks.KeyObserverMock)
		action     func(t *testing.T, provider *certificateProvider) error
		assert     func(t *testing.T, err error, provider *certificateProvider)
	}{
		"fails on secret resolution failure": {
			setupMocks: func(t *testing.T, sm *secretsmocks.ManagerMock, _ *keyregistrymocks.KeyObserverMock) {
				t.Helper()

				sm.EXPECT().
					ResolveSecret(mock.Anything, secrets.InternalRef("tls", "server")).
					Return(nil, errors.New("boom"))
			},
			assert: func(t *testing.T, err error, _ *certificateProvider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed resolving TLS secret")
			},
		},
		"fails for non asymmetric secret": {
			setupMocks: func(t *testing.T, sm *secretsmocks.ManagerMock, _ *keyregistrymocks.KeyObserverMock) {
				t.Helper()

				sm.EXPECT().
					ResolveSecret(mock.Anything, secrets.InternalRef("tls", "server")).
					Return(wrongType, nil)
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

				sm.EXPECT().
					ResolveSecret(mock.Anything, secrets.InternalRef("tls", "server")).
					Return(invalid, nil)
			},
			assert: func(t *testing.T, err error, _ *certificateProvider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "no certificate present")
			},
		},
		"successful reload": {
			setupMocks: func(t *testing.T, sm *secretsmocks.ManagerMock, ko *keyregistrymocks.KeyObserverMock) {
				t.Helper()

				sm.EXPECT().
					ResolveSecret(mock.Anything, secrets.InternalRef("tls", "server")).
					Return(valid, nil)
				ko.EXPECT().Notify(keyInfoMatching(valid)).Return()
			},
			assert: func(t *testing.T, err error, provider *certificateProvider) {
				t.Helper()

				require.NoError(t, err)

				cert := provider.cert.Load()
				require.Equal(t, valid.CertChain()[0], cert.Leaf)
			},
		},
		"keeps last known good certificate on reload failure": {
			setupMocks: func(t *testing.T, sm *secretsmocks.ManagerMock, ko *keyregistrymocks.KeyObserverMock) {
				t.Helper()

				callNum := 0

				ko.EXPECT().Notify(keyInfoMatching(valid)).Return()
				sm.EXPECT().
					ResolveSecret(mock.Anything, secrets.InternalRef("tls", "server")).
					RunAndReturn(func(_ context.Context, _ secrets.Reference) (secrets.Secret, error) {
						callNum++
						if callNum == 1 {
							return valid, nil
						}

						return wrongType, nil
					})
			},
			action: func(t *testing.T, provider *certificateProvider) error {
				t.Helper()

				require.NoError(t, provider.reload(t.Context()))

				return provider.reload(t.Context())
			},
			assert: func(t *testing.T, err error, provider *certificateProvider) {
				t.Helper()

				require.Error(t, err)

				cert := provider.cert.Load()
				require.Equal(t, valid.CertChain()[0], cert.Leaf)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			sm := secretsmocks.NewManagerMock(t)
			ko := keyregistrymocks.NewKeyObserverMock(t)
			provider := &certificateProvider{
				sr: secrets.InternalRef("tls", "server"),
				sm: sm,
				ko: ko,
			}

			action := x.IfThenElse(
				tc.action != nil,
				tc.action,
				func(t *testing.T, provider *certificateProvider) error {
					t.Helper()

					return provider.reload(t.Context())
				},
			)

			tc.setupMocks(t, sm, ko)

			err := action(t, provider)

			tc.assert(t, err, provider)
		})
	}
}

func TestCertificateProviderCertificate(t *testing.T) {
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
	tlsCert, err := toTLSCertificate(secret)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, provider *certificateProvider, cc *compatibilityCheckerMock)
		assert func(t *testing.T, err error, cert *tls.Certificate)
	}{
		"returns compatibility checker error": {
			setup: func(t *testing.T, provider *certificateProvider, cc *compatibilityCheckerMock) {
				t.Helper()

				provider.cert.Store(tlsCert)
				cc.EXPECT().SupportsCertificate(tlsCert).Return(errors.New("not supported"))
			},
			assert: func(t *testing.T, err error, _ *tls.Certificate) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "not supported")
			},
		},
		"succeeds with certificate from cache": {
			setup: func(t *testing.T, provider *certificateProvider, cc *compatibilityCheckerMock) {
				t.Helper()

				provider.cert.Store(tlsCert)
				cc.EXPECT().SupportsCertificate(tlsCert).Return(nil)
			},
			assert: func(t *testing.T, err error, cert *tls.Certificate) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cert)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			provider := &certificateProvider{}
			cc := newCompatibilityCheckerMock(t)

			tc.setup(t, provider, cc)
			cert, err := provider.certificate(cc)

			tc.assert(t, err, cert)
		})
	}
}

func TestToTLSCertificate(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T) types.AsymmetricKeySecret
		assert func(t *testing.T, cert *tls.Certificate, err error)
	}{
		"fails without certificate chain": {
			setup: func(t *testing.T) types.AsymmetricKeySecret {
				t.Helper()

				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)

				return types.NewAsymmetricKeySecret("tls", "server", "key1", key, nil)
			},
			assert: func(t *testing.T, cert *tls.Certificate, err error) {
				t.Helper()

				assert.Nil(t, cert)
				require.ErrorIs(t, err, errNoCertificatePresent)
			},
		},
		"creates tls certificate from full chain": {
			setup: func(t *testing.T) types.AsymmetricKeySecret {
				t.Helper()

				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)

				rootCA, err := testsupport.NewRootCA("Test Root CA", 24*time.Hour)
				require.NoError(t, err)

				leaf, err := rootCA.IssueCertificate(
					testsupport.WithSubject(pkix.Name{CommonName: "leaf"}),
					testsupport.WithValidity(time.Now(), 12*time.Hour),
					testsupport.WithSubjectPubKey(&key.PublicKey, x509.ECDSAWithSHA384),
					testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
				)
				require.NoError(t, err)

				return types.NewAsymmetricKeySecret(
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
