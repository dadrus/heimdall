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

package oauth2

type Confirmation struct {
	JWKThumbprint               string `json:"jkt,omitempty"`
	CertificateThumbprintSHA256 string `json:"x5t#S256,omitempty"` //nolint:tagliatelle
}

// Claims represents public claim values (as specified in RFC 7519).
type Claims struct {
	Issuer       string        `json:"iss,omitempty"`
	Subject      string        `json:"sub,omitempty"`
	Audience     Audience      `json:"aud,omitempty"`
	Scp          Scopes        `json:"scp,omitempty"`
	Scope        Scopes        `json:"scope,omitempty"`
	Expiry       *NumericDate  `json:"exp,omitempty"`
	NotBefore    *NumericDate  `json:"nbf,omitempty"`
	IssuedAt     *NumericDate  `json:"iat,omitempty"`
	JTI          string        `json:"jti,omitempty"`
	Confirmation *Confirmation `json:"cnf,omitempty"`
	ClientID     string        `json:"client_id,omitempty"`
	TokenType    TokenType     `json:"token_type,omitempty"`
}
