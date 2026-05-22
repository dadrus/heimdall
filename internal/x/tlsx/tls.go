package tlsx

import (
	"context"
	"crypto/tls"
	"errors"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/keyregistry"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var errNoCertificatePresent = errors.New("no certificate present")

type certificateRequest interface {
	SupportsCertificate(c *tls.Certificate) error
	Context() context.Context
}

func getCertificate(
	w *secrets.SecretInformer[*tls.Certificate],
	cr certificateRequest,
) (*tls.Certificate, error) {
	cert, ok := w.Get(cr.Context())
	if !ok {
		return nil, errNoCertificatePresent
	}

	if err := cr.SupportsCertificate(cert); err != nil {
		return nil, err
	}

	return cert, nil
}

func toTLSCertificate(secret secrets.Secret) (*tls.Certificate, error) {
	aks, ok := secret.(secrets.AsymmetricKeySecret)
	if !ok {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"secret is not suitable for TLS",
		)
	}

	chain := aks.CertChain()
	if len(chain) == 0 {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"secret is not suitable for TLS",
		)
	}

	cert := &tls.Certificate{
		PrivateKey: aks.PrivateKey(),
		Leaf:       chain[0],
	}

	for _, cer := range chain {
		cert.Certificate = append(cert.Certificate, cer.Raw)
	}

	return cert, nil
}

func newBaseTLSConfig(tlsCfg *config.TLS) *tls.Config {
	// nolint:gosec
	// configuration ensures, TLS versions below 1.2 are not possible
	cfg := &tls.Config{
		MinVersion: tlsCfg.MinVersion.OrDefault(),
		NextProtos: []string{"h2", "http/1.1"},
	}

	if cfg.MinVersion != tls.VersionTLS13 {
		cfg.CipherSuites = tlsCfg.CipherSuites.OrDefault()
	}

	return cfg
}

func newCertificateInformer(
	ctx context.Context,
	tlsCfg *config.TLS,
	sr secrets.Resolver,
	ko keyregistry.KeyObserver,
) (*secrets.SecretInformer[*tls.Certificate], error) {
	informer, err := secrets.NewSecretInformer(
		ctx,
		sr,
		secrets.Reference{Source: tlsCfg.Secret.Source, Selector: tlsCfg.Secret.Selector},
		secrets.InformerOptions[*tls.Certificate]{
			Converter:   toTLSCertificate,
			ResolveMode: secrets.ResolveEager,
			OnUpdate: func(ctx context.Context, secret secrets.Secret, _ *tls.Certificate) {
				ko.Notify(keyregistry.KeyInfo{
					Key:        secret.(secrets.AsymmetricKeySecret), //nolint:forcetypeassert
					Exportable: false,
				})
			},
		},
	)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed resolving TLS secret",
		).CausedBy(err)
	}

	return informer, nil
}

func ToClientTLSConfig(
	ctx context.Context,
	sr secrets.Resolver,
	tlsCfg *config.TLS,
	ko keyregistry.KeyObserver,
) (*tls.Config, error) {
	cfg := newBaseTLSConfig(tlsCfg)

	if len(tlsCfg.Secret.Source) == 0 {
		return cfg, nil
	}

	certResolver, err := newCertificateInformer(ctx, tlsCfg, sr, ko)
	if err != nil {
		return nil, err
	}

	cfg.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return getCertificate(certResolver, info)
	}

	return cfg, nil
}

func ToServerTLSConfig(
	ctx context.Context,
	sr secrets.Resolver,
	tlsCfg *config.TLS,
	ko keyregistry.KeyObserver,
) (*tls.Config, error) {
	certResolver, err := newCertificateInformer(ctx, tlsCfg, sr, ko)
	if err != nil {
		return nil, err
	}

	cfg := newBaseTLSConfig(tlsCfg)
	cfg.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return getCertificate(certResolver, info)
	}

	return cfg, nil
}
