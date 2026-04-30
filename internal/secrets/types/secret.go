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
	"fmt"
)

var ErrSecretTypeMismatch = errors.New("secret type mismatch")

type SecretType string

const (
	SecretTypePlain      SecretType = "plain"
	SecretTypeSymmetric  SecretType = "symmetric"
	SecretTypeAsymmetric SecretType = "asymmetric"
)

type Secret struct {
	KeyID     string
	Algorithm string
	KeySize   int
	Type      SecretType
	Value     any
	CertChain []*x509.Certificate
}

func (s Secret) AsString() (string, error) {
	value, ok := s.Value.(string)
	if !ok {
		return "", fmt.Errorf("%w: value does not implement string", ErrSecretTypeMismatch)
	}

	return value, nil
}

func (s Secret) AsBytes() ([]byte, error) {
	value, ok := s.Value.([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: value does not implement []byte", ErrSecretTypeMismatch)
	}

	return value, nil
}

func (s Secret) AsSigner() (crypto.Signer, error) {
	value, ok := s.Value.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: value does not implement crypto.Signer", ErrSecretTypeMismatch)
	}

	return value, nil
}
