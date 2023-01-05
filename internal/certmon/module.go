package certmon

import (
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/truststore"
)

var Module = fx.Options( //nolint:gochecknoglobals
	fx.Invoke(collectCertificateMetrics),
)

func registerCertificates(registerer prometheus.Registerer, service string, certSore string) {
	// Errors are ignored by intention. If these happen, heimdall won't start anyway
	certs, _ := truststore.NewTrustStoreFromPEMFile(certSore, false)

	for _, cert := range certs {
		registerer.MustRegister(NewCertificateExpirationCollector(service, cert))
	}
}

func collectCertificateMetrics(conf *config.Configuration, registerer prometheus.Registerer) {
	if conf.Serve.Decision.TLS != nil {
		registerCertificates(registerer, "decision", conf.Serve.Decision.TLS.KeyStore)
	}

	if conf.Serve.Proxy.TLS != nil {
		registerCertificates(registerer, "proxy", conf.Serve.Proxy.TLS.KeyStore)
	}

	if conf.Serve.Management.TLS != nil {
		registerCertificates(registerer, "management", conf.Serve.Management.TLS.KeyStore)
	}

	registerCertificates(registerer, "signer", conf.Signer.KeyStore)
}
