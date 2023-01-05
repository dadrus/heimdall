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
	"github.com/dadrus/heimdall/internal/truststore"
)

var Module = fx.Options( //nolint:gochecknoglobals
	fx.Provide(initPrometheusRegistry),
)

func initPrometheusRegistry(conf *config.Configuration) (prometheus.Registerer, prometheus.Gatherer) {
	reg := prometheus.NewRegistry()

	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(collectors.NewGoCollector(collectors.WithGoCollectorRuntimeMetrics(collectors.MetricsAll)))

	if conf.Serve.Decision.TLS != nil {
		registerCertificates(reg, "decision", conf.Serve.Decision.TLS.KeyStore)
	}

	if conf.Serve.Proxy.TLS != nil {
		registerCertificates(reg, "proxy", conf.Serve.Proxy.TLS.KeyStore)
	}

	if conf.Serve.Management.TLS != nil {
		registerCertificates(reg, "management", conf.Serve.Management.TLS.KeyStore)
	}

	registerCertificates(reg, "signer", conf.Signer.KeyStore)

	return reg, reg
}

func registerCertificates(registerer prometheus.Registerer, service string, certSore string) {
	// Errors are ignored by intention. If these happen, heimdall won't start anyway
	certs, _ := truststore.NewTrustStoreFromPEMFile(certSore, false)

	for _, cert := range certs {
		registerer.MustRegister(NewCertificateExpirationCollector(service, cert))
	}
}
