// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package types //nolint:revive

import (
	"crypto"
	"crypto/x509"
)

type SecretKind string

const (
	SecretKindString            SecretKind = "string"
	SecretKindSymmetricKey      SecretKind = "symmetric_key"  //nolint:gosec
	SecretKindAsymmetricKey     SecretKind = "asymmetric_key" //nolint:gosec
	SecretKindCertificateBundle SecretKind = "certificate_bundle"
	SecretKindCredentials       SecretKind = "credentials"
)

type Secret interface {
	Selector() string
	Kind() SecretKind
}

type StringSecret interface {
	Secret
	Value() string
}

type SymmetricKeySecret interface {
	Secret
	KeyID() string
	Key() []byte
	Algorithm() string
}

type AsymmetricKeySecret interface {
	Secret
	KeyID() string
	PrivateKey() crypto.Signer
	CertChain() []*x509.Certificate
}

type CertificateBundle interface {
	Secret
	Certificates() []*x509.Certificate
}

type Credentials interface {
	Secret
	Values() map[string]any
}

type baseSecret struct {
	selector string
	kind     SecretKind
}

func (s baseSecret) Selector() string { return s.selector }
func (s baseSecret) Kind() SecretKind { return s.kind }

type stringSecret struct {
	baseSecret

	value string
}

func NewStringSecret(selector, value string) StringSecret {
	return &stringSecret{
		baseSecret: baseSecret{
			selector: selector,
			kind:     SecretKindString,
		},
		value: value,
	}
}

func (s *stringSecret) Value() string { return s.value }

type symmetricKeySecret struct {
	baseSecret

	keyID     string
	value     []byte
	algorithm string
}

func NewSymmetricKeySecret(selector, kid, algorithm string, value []byte) SymmetricKeySecret {
	return &symmetricKeySecret{
		baseSecret: baseSecret{
			selector: selector,
			kind:     SecretKindSymmetricKey,
		},
		keyID:     kid,
		value:     value,
		algorithm: algorithm,
	}
}

func (s *symmetricKeySecret) KeyID() string     { return s.keyID }
func (s *symmetricKeySecret) Key() []byte       { return s.value }
func (s *symmetricKeySecret) Algorithm() string { return s.algorithm }

type asymmetricKeySecret struct {
	baseSecret

	keyID     string
	signer    crypto.Signer
	certChain []*x509.Certificate
}

func NewAsymmetricKeySecret(
	selector, kid string,
	signer crypto.Signer,
	certChain []*x509.Certificate,
) AsymmetricKeySecret {
	return &asymmetricKeySecret{
		baseSecret: baseSecret{
			selector: selector,
			kind:     SecretKindAsymmetricKey,
		},
		keyID:     kid,
		signer:    signer,
		certChain: certChain,
	}
}

func (s *asymmetricKeySecret) KeyID() string                  { return s.keyID }
func (s *asymmetricKeySecret) PrivateKey() crypto.Signer      { return s.signer }
func (s *asymmetricKeySecret) CertChain() []*x509.Certificate { return s.certChain }

type certificateBundle struct {
	baseSecret

	certs []*x509.Certificate
}

func NewCertificateBundle(selector string, certs []*x509.Certificate) CertificateBundle {
	return &certificateBundle{
		baseSecret: baseSecret{
			selector: selector,
			kind:     SecretKindCertificateBundle,
		},
		certs: certs,
	}
}

func (s *certificateBundle) Certificates() []*x509.Certificate { return s.certs }

type credentials struct {
	baseSecret

	values map[string]any
}

func NewCredentials(selector string, values map[string]any) Credentials {
	return &credentials{
		baseSecret: baseSecret{
			kind:     SecretKindCredentials,
			selector: selector,
		},
		values: values,
	}
}

func (p *credentials) Selector() string       { return p.selector }
func (p *credentials) Values() map[string]any { return p.values }
