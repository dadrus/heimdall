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
	"context"
	"crypto/x509"

	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type certStore []*x509.Certificate

func (s certStore) getSecret(_ context.Context, _ provider.Selector) (provider.Secret, error) {
	return nil, provider.ErrUnsupportedOperation
}

func (s certStore) getSecretSet(_ context.Context, _ provider.Selector) ([]provider.Secret, error) {
	return nil, provider.ErrUnsupportedOperation
}

func (s certStore) getCertificateBundle(_ context.Context, _ provider.Selector) (provider.CertificateBundle, error) {
	return provider.NewCertificateBundle("", s), nil
}

func (s certStore) sameKind(other store) bool {
	_, ok := other.(certStore)

	return ok
}

func newCertificateStoreFromPEMBytes(contents []byte) (certStore, error) {
	blocks := readPEMBlocks(contents)
	certs := make([]*x509.Certificate, 0, len(blocks))

	for idx, block := range blocks {
		if block.Type != pemBlockTypeCertificate {
			return nil, errorchain.NewWithMessagef(provider.ErrInternal,
				"unsupported entry '%s' in the pem file", block.Type)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errorchain.NewWithMessagef(provider.ErrInternal,
				"failed to parse %d entry in the pem file", idx).CausedBy(err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errorchain.NewWithMessage(provider.ErrConfiguration,
			"no certificate material present in the certificate store")
	}

	return certs, nil
}
