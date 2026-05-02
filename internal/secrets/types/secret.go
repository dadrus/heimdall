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
	"errors"

	"github.com/go-viper/mapstructure/v2"
)

var ErrSecretKindMismatch = errors.New("secret kind mismatch")

type SecretKind string

const (
	SecretKindString     SecretKind = "string"
	SecretKindBytes      SecretKind = "bytes"
	SecretKindSigner     SecretKind = "signer"
	SecretKindTrustStore SecretKind = "trust_store"
)

type Secret interface {
	Source() string
	Ref() string
	Kind() SecretKind
}

type StringSecret interface {
	Secret
	String() string
}

type BytesSecret interface {
	Secret
	Bytes() []byte
}

type SignerSecret interface {
	Secret
	KeyID() string
	Signer() crypto.Signer
	CertChain() []*x509.Certificate
}

type TrustStoreSecret interface {
	Secret
	CertPool() *x509.CertPool
}

type Credentials interface {
	Source() string
	Ref() string
	Decode(out any) error
}

type baseSecret struct {
	source string
	ref    string
	kind   SecretKind
}

func (s baseSecret) Source() string   { return s.source }
func (s baseSecret) Ref() string      { return s.ref }
func (s baseSecret) Kind() SecretKind { return s.kind }

type stringSecret struct {
	baseSecret

	value string
}

func NewStringSecret(source, ref, value string) StringSecret {
	return &stringSecret{
		baseSecret: baseSecret{
			source: source,
			ref:    ref,
			kind:   SecretKindString,
		},
		value: value,
	}
}

func (s *stringSecret) String() string { return s.value }

type bytesSecret struct {
	baseSecret

	value []byte
}

func NewBytesSecret(source, ref string, value []byte) BytesSecret {
	return &bytesSecret{
		baseSecret: baseSecret{
			source: source,
			ref:    ref,
			kind:   SecretKindBytes,
		},
		value: value,
	}
}

func (s *bytesSecret) Bytes() []byte { return s.value }

type signerSecret struct {
	baseSecret

	keyID     string
	signer    crypto.Signer
	certChain []*x509.Certificate
}

func NewSignerSecret(source, ref, kid string, signer crypto.Signer, certChain []*x509.Certificate) SignerSecret {
	return &signerSecret{
		baseSecret: baseSecret{
			source: source,
			ref:    ref,
			kind:   SecretKindSigner,
		},
		keyID:     kid,
		signer:    signer,
		certChain: certChain,
	}
}

func (s *signerSecret) KeyID() string                  { return s.keyID }
func (s *signerSecret) Signer() crypto.Signer          { return s.signer }
func (s *signerSecret) CertChain() []*x509.Certificate { return s.certChain }

type trustStoreSecret struct {
	baseSecret

	certPool *x509.CertPool
}

func NewTrustStoreSecret(source, ref string, certs []*x509.Certificate) TrustStoreSecret {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}

	return &trustStoreSecret{
		baseSecret: baseSecret{
			source: source,
			ref:    ref,
			kind:   SecretKindTrustStore,
		},
		certPool: pool,
	}
}

func (s *trustStoreSecret) CertPool() *x509.CertPool { return s.certPool }

type credentials struct {
	source string
	ref    string
	values map[string]Secret
}

func NewCredentials(source, ref string, values map[string]Secret) Credentials {
	return &credentials{
		source: source,
		ref:    ref,
		values: values,
	}
}

func (p *credentials) Source() string { return p.source }
func (p *credentials) Ref() string    { return p.ref }

func (p *credentials) Decode(out any) error {
	raw := make(map[string]any, len(p.values))

	for key, secret := range p.values {
		switch typed := secret.(type) {
		case StringSecret:
			raw[key] = typed.String()
		case BytesSecret:
			raw[key] = typed.Bytes()
		default:
			return ErrSecretKindMismatch
		}
	}

	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      out,
		ErrorUnused: true,
	})
	if err != nil {
		return err
	}

	return dec.Decode(raw)
}
