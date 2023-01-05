// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package prometheus

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x"
)

var Module = fx.Options( //nolint:gochecknoglobals
	fx.Provide(initPrometheusRegistry),
)

func initPrometheusRegistry(conf *config.Configuration) (prometheus.Registerer, prometheus.Gatherer) {
	reg := prometheus.NewRegistry()

	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(collectors.NewGoCollector(collectors.WithGoCollectorRuntimeMetrics(collectors.MetricsAll)))

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

	reg.MustRegister(NewCertificateExpirationCollector(
		WithServiceKeyStore("decision", decisionSrvKS,
			x.IfThenElse(len(decisionSrvKeyID) != 0, WithKeyID(decisionSrvKeyID), WithFirstEntry())),
		WithServiceKeyStore("proxy", proxySrvKS,
			x.IfThenElse(len(proxySrvKeyID) != 0, WithKeyID(proxySrvKeyID), WithFirstEntry())),
		WithServiceKeyStore("management", managementSrvKS,
			x.IfThenElse(len(managementSrvKeyID) != 0, WithKeyID(managementSrvKeyID), WithFirstEntry())),
		WithServiceKeyStore("signer", signerKS,
			x.IfThenElse(len(signerKeyID) != 0, WithKeyID(signerKeyID), WithFirstEntry())),
		WithEndEntityMonitoringOnly(false),
	))

	return reg, reg
}
