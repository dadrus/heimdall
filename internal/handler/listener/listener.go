package listener

import (
	"crypto/tls"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"net"

	"github.com/gofiber/fiber/v2"

	"github.com/dadrus/heimdall/internal/config"
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
	cert, err := tls.LoadX509KeyPair(conf.TLS.Cert, conf.TLS.Key)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed loading key and certificate").
			CausedBy(err)
	}

	tlsHandler := &fiber.TLSHandler{}

	// nolint:gosec
	// configuration ensures, TLS versions below 1.2 are not possible
	cfg := &tls.Config{
		Certificates:   []tls.Certificate{cert},
		MinVersion:     conf.TLS.MinVersion.OrDefault(),
		GetCertificate: tlsHandler.GetClientInfo,
	}

	if cfg.MinVersion < tls.VersionTLS13 {
		cfg.CipherSuites = conf.TLS.CipherSuites.OrDefault()
	}

	return tls.NewListener(listener, cfg), nil
}
