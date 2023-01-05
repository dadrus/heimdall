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
)

var Module = fx.Options( //nolint:gochecknoglobals
	fx.Provide(initPrometheusRegistry),
)

func initPrometheusRegistry(conf *config.Configuration) (prometheus.Registerer, prometheus.Gatherer) {
	reg := prometheus.NewRegistry()

	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(collectors.NewGoCollector(collectors.WithGoCollectorRuntimeMetrics(collectors.MetricsAll)))

	if conf.Serve.Decision.TLS != nil {
		registerCertificate(reg,
			"decision", conf.Serve.Decision.TLS.KeyStore, conf.Serve.Decision.TLS.KeyID)
	}

	if conf.Serve.Proxy.TLS != nil {
		registerCertificate(reg,
			"proxy", conf.Serve.Proxy.TLS.KeyStore, conf.Serve.Proxy.TLS.KeyID)
	}

	if conf.Serve.Management.TLS != nil {
		registerCertificate(reg,
			"management", conf.Serve.Management.TLS.KeyStore, conf.Serve.Management.TLS.KeyID)
	}

	registerCertificate(reg,
		"signer", conf.Signer.KeyStore, conf.Signer.KeyID)

	return reg, reg
}

func registerCertificate(reg prometheus.Registerer, service string, keyStore config.KeyStore, keyID string) {
	// Note: Errors are ignored by intention. If these happen, heimdall won't start anyway
	if len(keyStore.Path) == 0 {
		// given key store is not configured
		return
	}

	ks, err := keystore.NewKeyStoreFromPEMFile(keyStore.Path, keyStore.Password)
	if err != nil {
		return
	}

	var entry *keystore.Entry

	if len(keyID) != 0 {
		entry, _ = ks.GetKey(keyID)
	} else {
		entries := ks.Entries()

		if len(entries) != 0 {
			entry = ks.Entries()[0]
		}
	}

	if entry != nil {
		for _, cert := range entry.CertChain {
			reg.MustRegister(NewCertificateExpirationCollector(service, cert))
		}
	}
}
