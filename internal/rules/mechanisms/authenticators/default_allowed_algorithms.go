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

package authenticators

import "github.com/go-jose/go-jose/v3"

func defaultAllowedAlgorithms() []string {
	// RSA PKCS v1.5 is not allowed by intention
	return []string{
		// ECDSA
		string(jose.ES256), string(jose.ES384), string(jose.ES512),
		// RSA-PSS
		string(jose.PS256), string(jose.PS384), string(jose.PS512),
	}
}
