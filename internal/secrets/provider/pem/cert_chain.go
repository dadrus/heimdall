// Copyright 2026 Dimitrij Drus
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package pem

import (
	"bytes"
	"crypto"
	"crypto/x509"

	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/pkix"
)

func findChain(key crypto.PublicKey, certPool []*x509.Certificate) []*x509.Certificate {
	publicKey, ok := key.(interface {
		Equal(other crypto.PublicKey) bool
	})
	if !ok {
		return nil
	}

	for _, cert := range certPool {
		if publicKey.Equal(cert.PublicKey) {
			return buildChain([]*x509.Certificate{cert}, certPool)
		}
	}

	return nil
}

func buildChain(chain []*x509.Certificate, certPool []*x509.Certificate) []*x509.Certificate {
	child := chain[len(chain)-1]

	for _, cert := range certPool {
		if child.Equal(cert) {
			continue
		}

		if isIssuerOf(child, cert) {
			return buildChain(append(chain, cert), certPool)
		}
	}

	return chain
}

func isIssuerOf(child, issuer *x509.Certificate) bool {
	if len(child.AuthorityKeyId) != 0 && len(issuer.SubjectKeyId) != 0 {
		return bytes.Equal(child.AuthorityKeyId, issuer.SubjectKeyId)
	}

	return bytes.Equal(child.RawIssuer, issuer.RawSubject)
}

func validateChain(chain []*x509.Certificate) error {
	// The validation of the chain happens without the usage of the system
	// trust store. Given the way how buildChain works, the last certificate
	// in the chain is considered to be the root of trust, the first is the
	// actual end entity certificate and all others are intermediates.
	// That also means that if the chain consists of just one certificate,
	// it is trusted explicitly.
	if len(chain) == 1 {
		return nil
	}

	const certificateCount = 2

	intermediates := make([]*x509.Certificate, 0, max(0, len(chain)-certificateCount))
	if len(chain) > certificateCount {
		intermediates = append(intermediates, chain[1:len(chain)-1]...)
	}

	err := pkix.ValidateCertificate(chain[0],
		pkix.WithRootCACertificates([]*x509.Certificate{chain[len(chain)-1]}),
		pkix.WithIntermediateCACertificates(intermediates),
	)
	if err != nil {
		return errorchain.NewWithMessage(provider.ErrConfiguration,
			"invalid certificate chain").CausedBy(err)
	}

	return nil
}
