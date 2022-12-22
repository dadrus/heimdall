package listener

import (
	"crypto/tls"
	"net"

	"github.com/gofiber/fiber/v2"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func New(network string, conf config.ServiceConfig) (net.Listener, error) {
	listener, err := net.Listen(network, conf.Address())
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed creating listener").
			CausedBy(err)
	}

	if conf.TLS != nil {
		return newTLSListener(conf, listener)
	}

	return listener, nil
}

func newTLSListener(conf config.ServiceConfig, listener net.Listener) (net.Listener, error) {
	var (
		entry *keystore.Entry
		err   error
	)

	ks, err := keystore.NewKeyStoreFromPEMFile(conf.TLS.KeyStore, conf.TLS.Password)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed loading keystore").
			CausedBy(err)
	}

	if len(conf.TLS.KeyID) != 0 {
		if entry, err = ks.GetKey(conf.TLS.KeyID); err != nil {
			return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"failed retrieving key from key store").CausedBy(err)
		}
	} else {
		entry = ks.Entries()[0]
	}

	cert, err := keystore.ToTLSCertificate(entry)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"key store entry is not suitable for TLS").CausedBy(err)
	}

	tlsHandler := &fiber.TLSHandler{}

	// nolint:gosec
	// configuration ensures, TLS versions below 1.2 are not possible
	cfg := &tls.Config{
		Certificates:   []tls.Certificate{cert},
		MinVersion:     conf.TLS.MinVersion.OrDefault(),
		GetCertificate: tlsHandler.GetClientInfo,
	}

	if cfg.MinVersion != tls.VersionTLS13 {
		cfg.CipherSuites = conf.TLS.CipherSuites.OrDefault()
	}

	return tls.NewListener(listener, cfg), nil
}
