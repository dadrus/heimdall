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

package pkix

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyUsageString(t *testing.T) {
	for _, tc := range []struct {
		usage x509.KeyUsage
		name  string
	}{
		{usage: x509.KeyUsageDigitalSignature, name: "DigitalSignature"},
		{usage: x509.KeyUsageContentCommitment, name: "ContentCommitment"},
		{usage: x509.KeyUsageKeyEncipherment, name: "KeyEncipherment"},
		{usage: x509.KeyUsageDataEncipherment, name: "DataEncipherment"},
		{usage: x509.KeyUsageKeyAgreement, name: "KeyAgreement"},
		{usage: x509.KeyUsageCertSign, name: "CertSign"},
		{usage: x509.KeyUsageCRLSign, name: "CRLSign"},
		{usage: x509.KeyUsageEncipherOnly, name: "EncipherOnly"},
		{usage: x509.KeyUsageDecipherOnly, name: "DecipherOnly"},
		{usage: 1000, name: "Unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.name, KeyUsage(tc.usage).String())
		})
	}
}
