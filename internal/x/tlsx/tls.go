package tlsx

import (
	"crypto/tls"
	"sync"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type compatibilityChecker interface {
	SupportsCertificate(c *tls.Certificate) error
}

type tlsKeyStore struct {
	keyStore config.KeyStore
	keyID    string

	tlsCert *tls.Certificate
	mut     sync.Mutex
}

func newTLSKeyStore(cks config.KeyStore, keyID string) (*tlsKeyStore, error) {
	ks := &tlsKeyStore{
		keyStore: cks,
		keyID:    keyID,
	}

	if err := ks.load(); err != nil {
		return nil, err
	}

	return ks, nil
}

func (cr *tlsKeyStore) load() error {
	if len(cr.keyStore.Path) == 0 {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration, "no path to tls key store specified")
	}

	ks, err := keystore.NewKeyStoreFromPEMFile(cr.keyStore.Path, cr.keyStore.Password)
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal, "failed loading keystore").
			CausedBy(err)
	}

	var entry *keystore.Entry

	if len(cr.keyID) != 0 {
		if entry, err = ks.GetKey(cr.keyID); err != nil {
			return errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"failed retrieving key from key store").CausedBy(err)
		}
	} else {
		entry = ks.Entries()[0]
	}

	cert, err := entry.TLSCertificate()
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"key store entry is not suitable for TLS").CausedBy(err)
	}

	cr.mut.Lock()
	cr.tlsCert = &cert
	cr.mut.Unlock()

	return nil
}

func (cr *tlsKeyStore) certificate(cc compatibilityChecker) (*tls.Certificate, error) {
	var cert *tls.Certificate

	cr.mut.Lock()
	cert = cr.tlsCert
	cr.mut.Unlock()

	if err := cc.SupportsCertificate(cert); err != nil {
		return nil, err
	}

	return cert, nil
}

func (cr *tlsKeyStore) OnChanged(log zerolog.Logger) {
	err := cr.load()
	if err != nil {
		log.Warn().Err(err).
			Str("_file", cr.keyStore.Path).
			Msg("TLS key store reload failed")
	} else {
		log.Info().
			Str("_file", cr.keyStore.Path).
			Msg("TLS key store reloaded")
	}
}

func ToTLSConfig(tlsCfg *config.TLS, opts ...Option) (*tls.Config, error) {
	var (
		args options
		ks   *tlsKeyStore
		err  error
	)

	for _, opt := range opts {
		opt(&args)
	}

	if args.serverAuthRequired || args.clientAuthRequired {
		if ks, err = newTLSKeyStore(tlsCfg.KeyStore, tlsCfg.KeyID); err != nil {
			return nil, err
		}

		if args.secretsWatcher != nil {
			if err = args.secretsWatcher.Add(ks.keyStore.Path, ks); err != nil {
				return nil, err
			}
		}
	}

	// nolint:gosec
	// configuration ensures, TLS versions below 1.2 are not possible
	cfg := &tls.Config{
		MinVersion: tlsCfg.MinVersion.OrDefault(),
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: x.IfThenElse(args.serverAuthRequired,
			func(info *tls.ClientHelloInfo) (*tls.Certificate, error) { return ks.certificate(info) },
			nil,
		),
		GetClientCertificate: x.IfThenElse(args.clientAuthRequired,
			func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) { return ks.certificate(info) },
			nil,
		),
	}

	if cfg.MinVersion != tls.VersionTLS13 {
		cfg.CipherSuites = tlsCfg.CipherSuites.OrDefault()
	}

	return cfg, nil
}
