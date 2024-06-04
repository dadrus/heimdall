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
	"sync"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

//go:generate mockery --name compatibilityChecker --structname compatibilityCheckerMock --inpackage --testonly

type compatibilityChecker interface {
	SupportsCertificate(c *tls.Certificate) error
}

type keyStore struct {
	path     string
	password string
	keyID    string

	tlsCert *tls.Certificate
	mut     sync.RWMutex
}

func newTLSKeyStore(path, keyID, password string) (*keyStore, error) {
	ks := &keyStore{
		path:     path,
		keyID:    keyID,
		password: password,
	}

	if err := ks.load(); err != nil {
		return nil, err
	}

	return ks, nil
}

func (cr *keyStore) load() error {
	if len(cr.path) == 0 {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration, "no path to tls key store specified")
	}

	ks, err := keystore.NewKeyStoreFromPEMFile(cr.path, cr.password)
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal, "failed loading keystore").
			CausedBy(err)
	}

	var entry *keystore.Entry

	if len(cr.keyID) != 0 {
		entry, err = ks.GetKey(cr.keyID)
	} else {
		entry, err = ks.Entries()[0], nil
	}

	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed retrieving key from key store").CausedBy(err)
	}

	cert, err := entry.TLSCertificate()
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"key store entry is not suitable for TLS").CausedBy(err)
	}

	cr.mut.Lock()
	cr.tlsCert = &cert
	cr.mut.Unlock()

	return nil
}

func (cr *keyStore) certificate(cc compatibilityChecker) (*tls.Certificate, error) {
	var cert *tls.Certificate

	cr.mut.RLock()
	cert = cr.tlsCert
	cr.mut.RUnlock()

	if err := cc.SupportsCertificate(cert); err != nil {
		return nil, err
	}

	return cert, nil
}

func (cr *keyStore) OnChanged(log zerolog.Logger) {
	err := cr.load()
	if err != nil {
		log.Warn().Err(err).
			Str("_file", cr.path).
			Msg("TLS key store reload failed")
	} else {
		log.Info().
			Str("_file", cr.path).
			Msg("TLS key store reloaded")
	}
}
