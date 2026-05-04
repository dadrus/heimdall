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
	"fmt"

	"github.com/go-viper/mapstructure/v2"
)

type SecretKind string

const (
	SecretKindString        SecretKind = "string"
	SecretKindSymmetricKey  SecretKind = "symmetric_key"
	SecretKindAsymmetricKey SecretKind = "asymmetric_key"
	SecretKindTrustStore    SecretKind = "trust_store"
)

type Secret interface {
	Source() string
	Selector() string
	Kind() SecretKind
}

type StringSecret interface {
	Secret
	String() string
}

type SymmetricKeySecret interface {
	Secret
	KeyID() string
	Key() []byte
}

type AsymmetricKeySecret interface {
	Secret
	KeyID() string
	PrivateKey() crypto.Signer
	CertChain() []*x509.Certificate
}

type TrustStoreSecret interface {
	Secret
	CertPool() *x509.CertPool
}

type Credentials interface {
	Source() string
	Selector() string
	Decode(out any) error
}

type baseSecret struct {
	source   string
	selector string
	kind     SecretKind
}

func (s baseSecret) Source() string   { return s.source }
func (s baseSecret) Selector() string { return s.selector }
func (s baseSecret) Kind() SecretKind { return s.kind }

type stringSecret struct {
	baseSecret

	value string
}

func NewStringSecret(source, selector, value string) StringSecret {
	return &stringSecret{
		baseSecret: baseSecret{
			source:   source,
			selector: selector,
			kind:     SecretKindString,
		},
		value: value,
	}
}

func (s *stringSecret) String() string { return s.value }

type symmetricKeySecret struct {
	baseSecret

	keyID string
	value []byte
}

func NewSymmetricKeySecret(source, selector, kid string, value []byte) SymmetricKeySecret {
	return &symmetricKeySecret{
		baseSecret: baseSecret{
			source:   source,
			selector: selector,
			kind:     SecretKindSymmetricKey,
		},
		keyID: kid,
		value: value,
	}
}

func (s *symmetricKeySecret) KeyID() string { return s.keyID }
func (s *symmetricKeySecret) Key() []byte   { return s.value }

type asymmetricKeySecret struct {
	baseSecret

	keyID     string
	signer    crypto.Signer
	certChain []*x509.Certificate
}

func NewAsymmetricKeySecret(
	source, selector, kid string,
	signer crypto.Signer,
	certChain []*x509.Certificate,
) AsymmetricKeySecret {
	return &asymmetricKeySecret{
		baseSecret: baseSecret{
			source:   source,
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

type trustStoreSecret struct {
	baseSecret

	certPool *x509.CertPool
}

func NewTrustStoreSecret(source, selector string, certs []*x509.Certificate) TrustStoreSecret {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}

	return &trustStoreSecret{
		baseSecret: baseSecret{
			source:   source,
			selector: selector,
			kind:     SecretKindTrustStore,
		},
		certPool: pool,
	}
}

func (s *trustStoreSecret) CertPool() *x509.CertPool { return s.certPool }

type credentials struct {
	source   string
	selector string
	values   map[string]Secret
}

func NewCredentials(source, selector string, values map[string]Secret) Credentials {
	return &credentials{
		source:   source,
		selector: selector,
		values:   values,
	}
}

func (p *credentials) Source() string   { return p.source }
func (p *credentials) Selector() string { return p.selector }

func (p *credentials) Decode(out any) error {
	raw := make(map[string]any, len(p.values))

	for key, secret := range p.values {
		switch typed := secret.(type) {
		case StringSecret:
			raw[key] = typed.String()
		case SymmetricKeySecret:
			raw[key] = typed.Key()
		default:
			return ErrSecretKindMismatch
		}
	}

	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      out,
		ErrorUnused: true,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSecretPayload, err)
	}

	if err = dec.Decode(raw); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSecretPayload, err)
	}

	return nil
}
