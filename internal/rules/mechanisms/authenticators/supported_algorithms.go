// Copyright 2022-2025 Dimitrij Drus <dadrus@gmx.de>
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

package authenticators

import "github.com/go-jose/go-jose/v4"

func supportedAlgorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{
		// ECDSA
		jose.ES256, jose.ES384, jose.ES512, jose.EdDSA,
		// RSA-PSS
		jose.PS256, jose.PS384, jose.PS512,
		// RSA PKCS1 v1.5
		jose.RS256, jose.RS384, jose.RS512,
		// HMAC
		jose.HS256, jose.HS384, jose.HS512,
	}
}
