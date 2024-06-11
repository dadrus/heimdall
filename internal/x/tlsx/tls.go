// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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

package tlsx

import (
	"crypto/tls"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/x"
)

func ToTLSConfig(tlsCfg *config.TLS, opts ...Option) (*tls.Config, error) {
	var (
		ks  *keyStore
		err error
	)

	args := newOptions()
	for _, opt := range opts {
		opt(args)
	}

	if args.serverAuthRequired || args.clientAuthRequired {
		if ks, err = newTLSKeyStore(tlsCfg.KeyStore.Path, tlsCfg.KeyID, tlsCfg.KeyStore.Password); err != nil {
			return nil, err
		}

		if err = args.secretsWatcher.Add(ks.path, ks); err != nil {
			return nil, err
		}

		args.certificateObserver.Add(&certificateSupplier{name: args.name, ks: ks})
	}

	// nolint:gosec
	// configuration ensures, TLS versions below 1.2 are not possible
	cfg := &tls.Config{
		MinVersion: tlsCfg.MinVersion.OrDefault(),
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: x.IfThenElse(args.serverAuthRequired,
			func(info *tls.ClientHelloInfo) (*tls.Certificate, error) { return ks.certificate(info) },
			nil,
		),
		GetClientCertificate: x.IfThenElse(args.clientAuthRequired,
			func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) { return ks.certificate(info) },
			nil,
		),
	}

	if cfg.MinVersion != tls.VersionTLS13 {
		cfg.CipherSuites = tlsCfg.CipherSuites.OrDefault()
	}

	return cfg, nil
}
