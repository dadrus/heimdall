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

package keystore

import (
	"crypto/tls"
	"errors"
)

var ErrNoCertificatePresent = errors.New("no certificate present")

func ToTLSCertificate(entry *Entry) (tls.Certificate, error) {
	if len(entry.CertChain) == 0 {
		return tls.Certificate{}, ErrNoCertificatePresent
	}

	cert := tls.Certificate{
		PrivateKey: entry.PrivateKey,
		Leaf:       entry.CertChain[0],
	}

	for _, cer := range entry.CertChain {
		cert.Certificate = append(cert.Certificate, cer.Raw)
	}

	return cert, nil
}
