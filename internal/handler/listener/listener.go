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

package listener

import (
	"crypto/tls"
	"net"

	"github.com/gofiber/fiber/v2"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func New(network string, conf config.ServiceConfig) (net.Listener, error) {
	listener, err := net.Listen(network, conf.Address())
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed creating listener").
			CausedBy(err)
	}

	if conf.TLS != nil {
		return newTLSListener(conf.TLS, listener)
	}

	return listener, nil
}

func newTLSListener(tlsConf *config.TLS, listener net.Listener) (net.Listener, error) {
	var (
		entry *keystore.Entry
		err   error
	)

	ks, err := keystore.NewKeyStoreFromPEMFile(tlsConf.KeyStore.Path, tlsConf.KeyStore.Password)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed loading keystore").
			CausedBy(err)
	}

	if len(tlsConf.KeyID) != 0 {
		if entry, err = ks.GetKey(tlsConf.KeyID); err != nil {
			return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"failed retrieving key from key store").CausedBy(err)
		}
	} else {
		entry = ks.Entries()[0]
	}

	cert, err := keystore.ToTLSCertificate(entry)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"key store entry is not suitable for TLS").CausedBy(err)
	}

	tlsHandler := &fiber.TLSHandler{}

	// nolint:gosec
	// configuration ensures, TLS versions below 1.2 are not possible
	cfg := &tls.Config{
		Certificates:   []tls.Certificate{cert},
		MinVersion:     tlsConf.MinVersion.OrDefault(),
		GetCertificate: tlsHandler.GetClientInfo,
	}

	if cfg.MinVersion != tls.VersionTLS13 {
		cfg.CipherSuites = tlsConf.CipherSuites.OrDefault()
	}

	return tls.NewListener(listener, cfg), nil
}
