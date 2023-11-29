// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

	dSrvTLSConf := conf.Serve.Decision.TLS
	pSrvTLSConf := conf.Serve.Proxy.TLS
	mSrvTLSConf := conf.Serve.Management.TLS

	if dSrvTLSConf != nil {
		decisionSrvKS, _ = keystore.NewKeyStoreFromPEMFile(dSrvTLSConf.KeyStore.Path, dSrvTLSConf.KeyStore.Password)
		decisionSrvKeyID = dSrvTLSConf.KeyID
	}

	if pSrvTLSConf != nil {
		proxySrvKS, _ = keystore.NewKeyStoreFromPEMFile(pSrvTLSConf.KeyStore.Path, pSrvTLSConf.KeyStore.Password)
		proxySrvKeyID = pSrvTLSConf.KeyID
	}

	if mSrvTLSConf != nil {
		managementSrvKS, _ = keystore.NewKeyStoreFromPEMFile(mSrvTLSConf.KeyStore.Path, mSrvTLSConf.KeyStore.Password)
		managementSrvKeyID = mSrvTLSConf.KeyID
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
