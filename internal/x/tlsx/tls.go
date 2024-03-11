package tlsx

import (
	"crypto/tls"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/x"
)

func ToTLSConfig(tlsCfg *config.TLS, opts ...Option) (*tls.Config, error) {
	var (
		args options
		ks   *keyStore
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
