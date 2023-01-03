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
	"crypto/sha1" // nolint: gosec
	"crypto/x509"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func SubjectKeyID(pubKey any) ([]byte, error) {
	// Subject Key Identifier support
	// https://www.ietf.org/rfc/rfc3280.txt (section 4.2.1.2)
	marshaledKey, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to calculated subject public key id").CausedBy(err)
	}

	subjKeyID := sha1.Sum(marshaledKey) // nolint: gosec

	return subjKeyID[:], nil
}
