package listener

import (
	"crypto/tls"
	"net"

	"github.com/gofiber/fiber/v2"

	"github.com/dadrus/heimdall/internal/config"
)

func New(network string, conf config.ServiceConfig) (net.Listener, error) {
	listener, err := net.Listen(network, conf.Address())
	if err != nil {
		return nil, err
	}

	if conf.TLS != nil {
		return newTLSListener(conf, listener)
	}

	return listener, nil
}

func newTLSListener(conf config.ServiceConfig, listener net.Listener) (net.Listener, error) {
	cert, err := tls.LoadX509KeyPair(conf.TLS.Cert, conf.TLS.Key)
	if err != nil {
		return nil, err
	}

	tlsHandler := &fiber.TLSHandler{}
	tlsVersion := conf.TLS.MinVersion.OrDefault()

	// nolint:gosec
	// configuration ensures, TLS versions below 1.2 are not possible
	cfg := &tls.Config{
		Certificates:   []tls.Certificate{cert},
		MinVersion:     tlsVersion,
		GetCertificate: tlsHandler.GetClientInfo,
	}

	if tlsVersion < tls.VersionTLS13 {
		cfg.CipherSuites = conf.TLS.CipherSuites.OrDefault()
	}

	return tls.NewListener(listener, cfg), nil
}
