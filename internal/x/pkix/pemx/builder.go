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

package pemx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

type (
	BlockOption func(*pem.Block)
	EntryOption func(*pem.Block) error
)

func WithHeader(key, value string) BlockOption {
	return func(block *pem.Block) {
		block.Headers[key] = value
	}
}

func WithX509Certificate(cert *x509.Certificate, opts ...BlockOption) EntryOption {
	return func(block *pem.Block) error {
		block.Type = "CERTIFICATE"
		block.Bytes = cert.Raw

		for _, opt := range opts {
			opt(block)
		}

		return nil
	}
}

func WithECDSAPublicKey(key *ecdsa.PublicKey, opts ...BlockOption) EntryOption {
	return func(block *pem.Block) error {
		raw, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return err
		}

		block.Type = "ECDSA PUBLIC KEY"
		block.Bytes = raw

		for _, opt := range opts {
			opt(block)
		}

		return nil
	}
}

func WithECDSAPrivateKey(key *ecdsa.PrivateKey, opts ...BlockOption) EntryOption {
	return func(block *pem.Block) error {
		raw, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}

		block.Type = "EC PRIVATE KEY"
		block.Bytes = raw

		for _, opt := range opts {
			opt(block)
		}

		return nil
	}
}

func WithRSAPrivateKey(key *rsa.PrivateKey, opts ...BlockOption) EntryOption {
	return func(block *pem.Block) error {
		block.Type = "RSA PRIVATE KEY"
		block.Bytes = x509.MarshalPKCS1PrivateKey(key)

		for _, opt := range opts {
			opt(block)
		}

		return nil
	}
}

func BuildPEM(opts ...EntryOption) ([]byte, error) {
	buf := new(bytes.Buffer)

	for _, opt := range opts {
		block := &pem.Block{Headers: make(map[string]string)}

		err := opt(block)
		if err != nil {
			return nil, err
		}

		if err = pem.Encode(buf, block); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}
