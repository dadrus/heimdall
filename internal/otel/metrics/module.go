package metrics

import (
	"go.opentelemetry.io/contrib/instrumentation/host"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/otel/metrics/certificate"
	"github.com/dadrus/heimdall/internal/x"
)

var Module = fx.Options( // nolint: gochecknoglobals
	fx.Invoke(runtime.Start),
	fx.Invoke(host.Start),
	fx.Invoke(monitorCertificateExpiry),
)

func monitorCertificateExpiry(conf *config.Configuration) error {
	var (
		decisionSrvKS   keystore.KeyStore
		proxySrvKS      keystore.KeyStore
		managementSrvKS keystore.KeyStore
		signerKS        keystore.KeyStore

		decisionSrvKeyID   string
		proxySrvKeyID      string
		managementSrvKeyID string
		signerKeyID        string
	)

	if conf.Serve.Decision.TLS != nil {
		decisionSrvKS, _ = keystore.NewKeyStoreFromPEMFile(
			conf.Serve.Decision.TLS.KeyStore.Path,
			conf.Serve.Decision.TLS.KeyStore.Password,
		)

		decisionSrvKeyID = conf.Serve.Decision.TLS.KeyID
	}

	if conf.Serve.Proxy.TLS != nil {
		proxySrvKS, _ = keystore.NewKeyStoreFromPEMFile(
			conf.Serve.Proxy.TLS.KeyStore.Path,
			conf.Serve.Proxy.TLS.KeyStore.Password,
		)

		proxySrvKeyID = conf.Serve.Proxy.TLS.KeyID
	}

	if conf.Serve.Management.TLS != nil {
		managementSrvKS, _ = keystore.NewKeyStoreFromPEMFile(
			conf.Serve.Management.TLS.KeyStore.Path,
			conf.Serve.Management.TLS.KeyStore.Password,
		)

		managementSrvKeyID = conf.Serve.Management.TLS.KeyID
	}

	signerKS, _ = keystore.NewKeyStoreFromPEMFile(
		conf.Signer.KeyStore.Path,
		conf.Signer.KeyStore.Password,
	)
	signerKeyID = conf.Signer.KeyID

	return certificate.Start(
		certificate.WithServiceKeyStore(
			"decision", decisionSrvKS,
			x.IfThenElse(len(decisionSrvKeyID) != 0,
				certificate.WithKeyID(decisionSrvKeyID),
				certificate.WithFirstEntry(),
			),
		),
		certificate.WithServiceKeyStore(
			"proxy",
			proxySrvKS,
			x.IfThenElse(len(proxySrvKeyID) != 0,
				certificate.WithKeyID(proxySrvKeyID),
				certificate.WithFirstEntry(),
			),
		),
		certificate.WithServiceKeyStore(
			"management",
			managementSrvKS,
			x.IfThenElse(len(managementSrvKeyID) != 0,
				certificate.WithKeyID(managementSrvKeyID),
				certificate.WithFirstEntry(),
			),
		),
		certificate.WithServiceKeyStore(
			"signer",
			signerKS,
			x.IfThenElse(len(signerKeyID) != 0,
				certificate.WithKeyID(signerKeyID),
				certificate.WithFirstEntry(),
			),
		),
		certificate.WithEndEntityMonitoringOnly(false),
	)
}
