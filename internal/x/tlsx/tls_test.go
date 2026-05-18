package tlsx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/keyregistry"
	keyregistrymocks "github.com/dadrus/heimdall/internal/keyregistry/mocks"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/secrets/informer"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestToServerTLSConfig(t *testing.T) {
	t.Parallel()

	secret := newTLSSecret(t)

	for uc, tc := range map[string]struct {
		conf   config.TLS
		setup  func(t *testing.T, sm *secretsmocks.ManagerMock, ko *keyregistrymocks.KeyObserverMock)
		assert func(t *testing.T, err error, cfg *tls.Config)
	}{
		"fails if secret resolution fails": {
			conf: config.TLS{
				Secret: config.Secret{Source: "tls", Selector: "server"},
			},
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock, _ *keyregistrymocks.KeyObserverMock) {
				t.Helper()

				sm.EXPECT().
					ResolveSecret(mock.Anything, secrets.InternalRef("tls", "server")).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, cfg *tls.Config) {
				t.Helper()

				assert.Nil(t, cfg)
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed resolving TLS secret")
			},
		},
		"successful": {
			conf: config.TLS{
				Secret:     config.Secret{Source: "tls", Selector: "server"},
				MinVersion: tls.VersionTLS12,
			},
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock, ko *keyregistrymocks.KeyObserverMock) {
				t.Helper()

				ko.EXPECT().
					Notify(mock.MatchedBy(func(ki keyregistry.KeyInfo) bool {
						return ki.Key.KeyID() == secret.KeyID() &&
							ki.Key.PrivateKey() == secret.PrivateKey() &&
							assert.ObjectsAreEqual(ki.Key.CertChain(), secret.CertChain()) &&
							!ki.Exportable
					}))

				sm.EXPECT().
					ResolveSecret(mock.Anything, secrets.InternalRef("tls", "server")).
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
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			sm := secretsmocks.NewManagerMock(t)
			ko := keyregistrymocks.NewKeyObserverMock(t)
			tc.setup(t, sm, ko)

			cfg, err := ToServerTLSConfig(t.Context(), sm, &tc.conf, ko)

			tc.assert(t, err, cfg)
		})
	}
}

func TestToClientTLSConfig(t *testing.T) {
	t.Parallel()

	secret := newTLSSecret(t)

	for uc, tc := range map[string]struct {
		conf   config.TLS
		setup  func(t *testing.T, sm *secretsmocks.ManagerMock, ko *keyregistrymocks.KeyObserverMock)
		assert func(t *testing.T, err error, cfg *tls.Config)
	}{
		"without client certificate secret": {
			conf: config.TLS{},
			setup: func(t *testing.T, _ *secretsmocks.ManagerMock, _ *keyregistrymocks.KeyObserverMock) {
				t.Helper()
			},
			assert: func(t *testing.T, err error, cfg *tls.Config) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cfg)
				assert.Nil(t, cfg.GetCertificate)
				assert.Nil(t, cfg.GetClientCertificate)
				assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
				assert.Empty(t, cfg.CipherSuites)
				assert.Equal(t, []string{"h2", "http/1.1"}, cfg.NextProtos)
			},
		},
		"fails if secret resolution fails": {
			conf: config.TLS{
				Secret: config.Secret{Source: "tls", Selector: "client"},
			},
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock, _ *keyregistrymocks.KeyObserverMock) {
				t.Helper()

				sm.EXPECT().
					ResolveSecret(mock.Anything, secrets.InternalRef("tls", "client")).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, cfg *tls.Config) {
				t.Helper()

				assert.Nil(t, cfg)
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed resolving TLS secret")
			},
		},
		"successful with client certificate secret": {
			conf: config.TLS{
				Secret: config.Secret{Source: "tls", Selector: "client"},
			},
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock, ko *keyregistrymocks.KeyObserverMock) {
				t.Helper()

				ko.EXPECT().
					Notify(mock.MatchedBy(func(ki keyregistry.KeyInfo) bool {
						return ki.Key.KeyID() == secret.KeyID() &&
							ki.Key.PrivateKey() == secret.PrivateKey() &&
							assert.ObjectsAreEqual(ki.Key.CertChain(), secret.CertChain()) &&
							!ki.Exportable
					}))

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
			t.Parallel()

			sm := secretsmocks.NewManagerMock(t)
			ko := keyregistrymocks.NewKeyObserverMock(t)
			tc.setup(t, sm, ko)

			cfg, err := ToClientTLSConfig(t.Context(), sm, &tc.conf, ko)

			tc.assert(t, err, cfg)
		})
	}
}

func TestGetCertificate(t *testing.T) {
	t.Parallel()

	secret := newTLSSecret(t)
	ref := secrets.InternalRef("tls", "server")

	for uc, tc := range map[string]struct {
		skipStart bool
		setup     func(t *testing.T, sm *secretsmocks.ManagerMock, cc *compatibilityCheckerMock)
		assert    func(t *testing.T, err error, cert *tls.Certificate)
	}{
		"fails if no certificate is available": {
			skipStart: true,
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock, _ *compatibilityCheckerMock) {
				t.Helper()
			},
			assert: func(t *testing.T, err error, _ *tls.Certificate) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, errNoCertificatePresent)
			},
		},
		"fails if certificate is incompatible": {
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock, cc *compatibilityCheckerMock) {
				t.Helper()

				sm.EXPECT().ResolveSecret(mock.Anything, ref).Return(secret, nil)
				sm.EXPECT().Subscribe(ref, mock.Anything).Return(func() {}, nil)
				cc.EXPECT().SupportsCertificate(mock.Anything).Return(assert.AnError)
			},
			assert: func(t *testing.T, err error, cert *tls.Certificate) {
				t.Helper()

				assert.Nil(t, cert)
				require.ErrorContains(t, err, assert.AnError.Error())
			},
		},
		"returns cached certificate": {
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock, cc *compatibilityCheckerMock) {
				t.Helper()

				sm.EXPECT().ResolveSecret(mock.Anything, ref).Return(secret, nil)
				sm.EXPECT().Subscribe(ref, mock.Anything).Return(func() {}, nil)
				cc.EXPECT().SupportsCertificate(mock.Anything).Return(nil)
			},
			assert: func(t *testing.T, err error, actual *tls.Certificate) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, actual)
				assert.NotNil(t, actual.PrivateKey)
				assert.NotNil(t, actual.Leaf)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			sm := secretsmocks.NewManagerMock(t)
			cc := newCompatibilityCheckerMock(t)
			tc.setup(t, sm, cc)

			resolver := &informer.SecretInformer[*tls.Certificate]{
				Manager:   sm,
				Reference: ref,
				Converter: toTLSCertificate,
			}

			if !tc.skipStart {
				err := resolver.Start(t.Context())
				require.NoError(t, err)
			}

			actual, err := getCertificate(resolver, cc)

			tc.assert(t, err, actual)
		})
	}
}

func TestToTLSCertificate(t *testing.T) {
	t.Parallel()

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

	for uc, tc := range map[string]struct {
		secret types.Secret
		assert func(t *testing.T, err error, cert *tls.Certificate)
	}{
		"fails for wrong secret type": {
			secret: types.NewStringSecret("server", "key1"),
			assert: func(t *testing.T, err error, _ *tls.Certificate) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "secret is not suitable for TLS")
			},
		},
		"fails without certificate chain": {
			secret: types.NewAsymmetricKeySecret("server", "key1", key, nil),
			assert: func(t *testing.T, err error, _ *tls.Certificate) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "secret is not suitable for TLS")
			},
		},
		"creates tls certificate from full chain": {
			secret: types.NewAsymmetricKeySecret(
				"server",
				"key1",
				key,
				[]*x509.Certificate{leaf, rootCA.Certificate},
			),
			assert: func(t *testing.T, err error, cert *tls.Certificate) {
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

			cert, err := toTLSCertificate(tc.secret)

			tc.assert(t, err, cert)
		})
	}
}

func newTLSSecret(t *testing.T) secrets.AsymmetricKeySecret {
	t.Helper()

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

	return types.NewAsymmetricKeySecret("server", "key1", key, []*x509.Certificate{cert})
}
