package tlsx

import (
	"context"
	"crypto/tls"
	"errors"
	"sync/atomic"

	"github.com/dadrus/heimdall/internal/keyregistry/v2"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var errNoCertificatePresent = errors.New("no certificate present")

type compatibilityChecker interface {
	SupportsCertificate(c *tls.Certificate) error
}

type certificateProvider struct {
	sr   secrets.Reference
	sm   secrets.Manager
	ko   keyregistry.KeyObserver
	cert atomic.Pointer[tls.Certificate]
}

func newCertificateProvider(
	ctx context.Context,
	ref secrets.Reference,
	sm secrets.Manager,
	ko keyregistry.KeyObserver,
) (*certificateProvider, error) {
	provider := &certificateProvider{
		sr: ref,
		sm: sm,
		ko: ko,
	}

	if err := provider.reload(ctx); err != nil {
		return nil, err
	}

	if _, err := sm.Subscribe(ref, func(ctx context.Context) error { return provider.reload(ctx) }); err != nil {
		return nil, err
	}

	return provider, nil
}

func (p *certificateProvider) reload(ctx context.Context) error {
	secret, err := p.sm.ResolveSecret(ctx, p.sr)
	if err != nil {
		return errorchain.NewWithMessage(pipeline.ErrConfiguration,
			"failed resolving secret").CausedBy(err)
	}

	aks, ok := secret.(secrets.AsymmetricKeySecret)
	if !ok {
		return errorchain.NewWithMessage(pipeline.ErrConfiguration,
			"secret is not suitable for TLS")
	}

	cert, err := toTLSCertificate(aks)
	if err != nil {
		return errorchain.NewWithMessage(pipeline.ErrConfiguration,
			"secret is not suitable for TLS").CausedBy(err)
	}

	p.ko.Notify(keyregistry.KeyInfo{Key: aks, Exportable: false})
	p.cert.Store(cert)

	return nil
}

func (p *certificateProvider) certificate(cc compatibilityChecker) (*tls.Certificate, error) {
	cert := p.cert.Load()

	if err := cc.SupportsCertificate(cert); err != nil {
		return nil, err
	}

	return cert, nil
}

func toTLSCertificate(secret secrets.AsymmetricKeySecret) (*tls.Certificate, error) {
	chain := secret.CertChain()
	if len(chain) == 0 {
		return nil, errNoCertificatePresent
	}

	cert := &tls.Certificate{
		PrivateKey: secret.PrivateKey(),
		Leaf:       chain[0],
	}

	for _, cer := range chain {
		cert.Certificate = append(cert.Certificate, cer.Raw)
	}

	return cert, nil
}
