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

import "crypto/x509"

var keyUsages = map[KeyUsage]string{ //nolint:gochecknoglobals
	KeyUsage(x509.KeyUsageDigitalSignature):  "DigitalSignature",
	KeyUsage(x509.KeyUsageContentCommitment): "ContentCommitment",
	KeyUsage(x509.KeyUsageKeyEncipherment):   "KeyEncipherment",
	KeyUsage(x509.KeyUsageDataEncipherment):  "DataEncipherment",
	KeyUsage(x509.KeyUsageKeyAgreement):      "KeyAgreement",
	KeyUsage(x509.KeyUsageCertSign):          "CertSign",
	KeyUsage(x509.KeyUsageCRLSign):           "CRLSign",
	KeyUsage(x509.KeyUsageEncipherOnly):      "EncipherOnly",
	KeyUsage(x509.KeyUsageDecipherOnly):      "DecipherOnly",
}

type KeyUsage x509.KeyUsage

func (k KeyUsage) String() string {
	if name, ok := keyUsages[k]; ok {
		return name
	}

	return "Unknown"
}
