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

package truststore

import (
	"crypto/x509"
	"os"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
)

const pemBlockTypeCertificate = "CERTIFICATE"

type TrustStore []*x509.Certificate

func (ts *TrustStore) addEntry(strict bool) pemx.PEMBlockCallback {
	return func(idx int, blockType string, _ map[string]string, content []byte) error {
		var (
			cert *x509.Certificate
			err  error
		)

		if blockType == pemBlockTypeCertificate {
			cert, err = x509.ParseCertificate(content)
			if err != nil {
				return errorchain.NewWithMessagef(heimdall.ErrInternal,
					"failed to parse %d entry in the pem file", idx).CausedBy(err)
			}

			*ts = append(*ts, cert)
		} else if strict {
			return errorchain.NewWithMessagef(heimdall.ErrInternal,
				"unsupported entry '%s' entry in the pem file", blockType)
		}

		return nil
	}
}

func (ts *TrustStore) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range *ts {
		pool.AddCert(cert)
	}

	return pool
}

func NewTrustStoreFromPEMFile(pemFilePath string, strict bool) (TrustStore, error) {
	fInfo, err := os.Stat(pemFilePath)
	if err != nil {
		return nil, err
	}

	if fInfo.IsDir() {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration, "'%s' is not a file", pemFilePath)
	}

	contents, err := os.ReadFile(pemFilePath)
	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to read %s", pemFilePath).CausedBy(err)
	}

	return NewTrustStoreFromPEMBytes(contents, strict)
}

func NewTrustStoreFromPEMBytes(pemBytes []byte, strict bool) (TrustStore, error) {
	var certs TrustStore

	err := pemx.ReadPEM(pemBytes, certs.addEntry(strict))

	return certs, err
}
