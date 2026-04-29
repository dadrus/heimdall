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

package joseadapter

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"

	"github.com/dadrus/heimdall/internal/keystore"
)

var (
	ErrNilEntry            = errors.New("nil keystore entry")
	ErrNoPublicKeyMaterial = errors.New("no public key material in keystore entry")
	ErrUnsupportedAlg      = errors.New("unsupported key algorithm")
	ErrUnsupportedKeySize  = errors.New("unsupported key size")
)

func ToJWK(entry *keystore.Entry) (jose.JSONWebKey, error) {
	if entry == nil {
		return jose.JSONWebKey{}, ErrNilEntry
	}

	alg, err := joseAlgorithm(entry.Alg, entry.KeySize)
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	pubKey, err := publicKeyFromEntry(entry)
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	return jose.JSONWebKey{
		KeyID:        entry.KeyID,
		Algorithm:    string(alg),
		Key:          pubKey,
		Use:          "sig",
		Certificates: entry.CertChain,
	}, nil
}

func joseAlgorithm(alg string, keySize int) (jose.SignatureAlgorithm, error) {
	switch alg {
	case keystore.AlgRSA:
		return rsaAlgorithm(keySize)
	case keystore.AlgECDSA:
		return ecdsaAlgorithm(keySize)
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedAlg, alg)
	}
}

func ecdsaAlgorithm(keySize int) (jose.SignatureAlgorithm, error) {
	switch keySize {
	case 256: //nolint:mnd
		return jose.ES256, nil
	case 384: //nolint:mnd
		return jose.ES384, nil
	case 521: // nolint:mnd
		return jose.ES512, nil
	default:
		return "", fmt.Errorf("%w for ecdsa: %d", ErrUnsupportedKeySize, keySize)
	}
}

func rsaAlgorithm(keySize int) (jose.SignatureAlgorithm, error) {
	switch keySize {
	case 2048: //nolint:mnd
		return jose.PS256, nil
	case 3072: //nolint:mnd
		return jose.PS384, nil
	case 4096: //nolint:mnd
		return jose.PS512, nil
	default:
		return "", fmt.Errorf("%w for rsa: %d", ErrUnsupportedKeySize, keySize)
	}
}

func publicKeyFromEntry(entry *keystore.Entry) (crypto.PublicKey, error) {
	if entry.PrivateKey != nil {
		return entry.PrivateKey.Public(), nil
	}

	if len(entry.CertChain) != 0 {
		return entry.CertChain[0].PublicKey, nil
	}

	return nil, ErrNoPublicKeyMaterial
}
