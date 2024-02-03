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

package config

import (
	"crypto/tls"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type TLSCipherSuites []uint16

func (s TLSCipherSuites) OrDefault() []uint16 {
	if len(s) == 0 {
		return []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		}
	}

	return s
}

type TLSMinVersion uint16

func (v TLSMinVersion) OrDefault() uint16 {
	if v == 0 {
		return tls.VersionTLS13
	}

	return uint16(v)
}

type KeyStore struct {
	Path     string `koanf:"path"     mapstructure:"path"`
	Password string `koanf:"password" mapstructure:"password"`
}

type TrustStore struct {
	Path string `koanf:"path" mapstructure:"path"`
}

type TLS struct {
	KeyStore     KeyStore        `koanf:"key_store"     mapstructure:"key_store"`
	KeyID        string          `koanf:"key_id"        mapstructure:"key_id"`
	CipherSuites TLSCipherSuites `koanf:"cipher_suites" mapstructure:"cipher_suites"`
	MinVersion   TLSMinVersion   `koanf:"min_version"   mapstructure:"min_version"`
}

func (t *TLS) TLSConfig() (*tls.Config, error) {
	var eeCerts []tls.Certificate

	if len(t.KeyStore.Path) != 0 { //nolint:nestif
		ks, err := keystore.NewKeyStoreFromPEMFile(t.KeyStore.Path, t.KeyStore.Password)
		if err != nil {
			return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed loading keystore").
				CausedBy(err)
		}

		var entry *keystore.Entry

		if len(t.KeyID) != 0 {
			if entry, err = ks.GetKey(t.KeyID); err != nil {
				return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
					"failed retrieving key from key store").CausedBy(err)
			}
		} else {
			entry = ks.Entries()[0]
		}

		cert, err := entry.TLSCertificate()
		if err != nil {
			return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"key store entry is not suitable for TLS").CausedBy(err)
		}

		eeCerts = []tls.Certificate{cert}
	}

	// nolint:gosec
	// configuration ensures, TLS versions below 1.2 are not possible
	cfg := &tls.Config{
		Certificates: eeCerts,
		MinVersion:   t.MinVersion.OrDefault(),
		NextProtos:   []string{"h2", "http/1.1"},
	}

	if cfg.MinVersion != tls.VersionTLS13 {
		cfg.CipherSuites = t.CipherSuites.OrDefault()
	}

	return cfg, nil
}
