package tlsx

import (
	"context"
	"crypto/tls"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x"
)

func ToTLSConfig(ctx context.Context, tlsCfg *config.TLS, opts ...Option) (*tls.Config, error) {
	var (
		certProvider *certificateProvider
		err          error
	)

	args := newOptions()
	for _, opt := range opts {
		opt(args)
	}

	if args.serverAuthRequired || args.clientAuthRequired {
		certProvider, err = newCertificateProvider(
			ctx,
			secrets.InternalRef(tlsCfg.Secret.Source, tlsCfg.Secret.Selector),
			args.secretsManager,
			args.keyObserver,
		)
		if err != nil {
			return nil, err
		}
	}

	// nolint:gosec
	// configuration ensures, TLS versions below 1.2 are not possible
	cfg := &tls.Config{
		MinVersion: tlsCfg.MinVersion.OrDefault(),
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: x.IfThenElse(args.serverAuthRequired,
			func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return certProvider.certificate(info)
			},
			nil,
		),
		GetClientCertificate: x.IfThenElse(args.clientAuthRequired,
			func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return certProvider.certificate(info)
			},
			nil,
		),
	}

	if cfg.MinVersion != tls.VersionTLS13 {
		cfg.CipherSuites = tlsCfg.CipherSuites.OrDefault()
	}

	return cfg, nil
}
