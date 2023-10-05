package certificate

import (
	"crypto/x509"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"

	"github.com/dadrus/heimdall/internal/keystore"
)

type config struct {
	provider           metric.MeterProvider
	services           []*service
	monitorEECertsOnly bool
}

type (
	Option     func(conf *config)
	CertGetter func(ks keystore.KeyStore) []*x509.Certificate
)

func WithMeterProvider(provider metric.MeterProvider) Option {
	return func(conf *config) {
		if provider != nil {
			conf.provider = provider
		}
	}
}

func WithKeyID(keyID string) CertGetter {
	return func(ks keystore.KeyStore) []*x509.Certificate {
		entry, err := ks.GetKey(keyID)
		if err != nil {
			return nil
		}

		return entry.CertChain
	}
}

func WithFirstEntry() CertGetter {
	return func(ks keystore.KeyStore) []*x509.Certificate {
		entries := ks.Entries()
		if len(entries) == 0 {
			return nil
		}

		return entries[0].CertChain
	}
}

func WithServiceCertificates(serviceName string, certs []*x509.Certificate) Option {
	return func(conf *config) {
		if len(certs) != 0 {
			conf.services = append(conf.services, &service{
				name:         serviceName,
				certificates: certs,
			})
		}
	}
}

func WithServiceKeyStore(serviceName string, ks keystore.KeyStore, certGetter CertGetter) Option {
	if ks != nil {
		return WithServiceCertificates(serviceName, certGetter(ks))
	}

	return func(conf *config) {}
}

func WithEndEntityMonitoringOnly(flag bool) Option {
	return func(conf *config) {
		conf.monitorEECertsOnly = flag
	}
}

func newConfig(opts ...Option) *config {
	conf := config{
		provider: otel.GetMeterProvider(),
	}

	for _, opt := range opts {
		opt(&conf)
	}

	return &conf
}
