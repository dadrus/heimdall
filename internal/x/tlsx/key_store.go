package tlsx

import (
	"crypto/tls"
	"sync"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type compatibilityChecker interface {
	SupportsCertificate(c *tls.Certificate) error
}

type keyStore struct {
	path     string
	password string
	keyID    string

	tlsCert *tls.Certificate
	mut     sync.Mutex
}

func newTLSKeyStore(path, keyID, password string) (*keyStore, error) {
	ks := &keyStore{
		path:     path,
		keyID:    keyID,
		password: password,
	}

	if err := ks.load(); err != nil {
		return nil, err
	}

	return ks, nil
}

func (cr *keyStore) load() error {
	if len(cr.path) == 0 {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration, "no path to tls key store specified")
	}

	ks, err := keystore.NewKeyStoreFromPEMFile(cr.path, cr.password)
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

func (cr *keyStore) certificate(cc compatibilityChecker) (*tls.Certificate, error) {
	var cert *tls.Certificate

	cr.mut.Lock()
	cert = cr.tlsCert
	cr.mut.Unlock()

	if err := cc.SupportsCertificate(cert); err != nil {
		return nil, err
	}

	return cert, nil
}

func (cr *keyStore) OnChanged(log zerolog.Logger) {
	err := cr.load()
	if err != nil {
		log.Warn().Err(err).
			Str("_file", cr.path).
			Msg("TLS key store reload failed")
	} else {
		log.Info().
			Str("_file", cr.path).
			Msg("TLS key store reloaded")
	}
}
