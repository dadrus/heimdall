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
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"

	"github.com/dadrus/heimdall/internal/secrets"
)

var (
	ErrNilEntry            = errors.New("nil keystore entry")
	ErrNoPublicKeyMaterial = errors.New("no public key material in keystore entry")
	ErrUnsupportedAlg      = errors.New("unsupported key algorithm")
	ErrUnsupportedKeySize  = errors.New("unsupported key size")
)

func ToJWK(secret secrets.AsymmetricKeySecret) (jose.JSONWebKey, error) {
	if secret == nil {
		return jose.JSONWebKey{}, ErrNilEntry
	}

	pubKey := secret.PrivateKey().Public()

	alg, err := joseAlgorithm(pubKey)
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	return jose.JSONWebKey{
		KeyID:        secret.KeyID(),
		Algorithm:    string(alg),
		Key:          pubKey,
		Use:          "sig",
		Certificates: secret.CertChain(),
	}, nil
}

func joseAlgorithm(pubKey crypto.PublicKey) (jose.SignatureAlgorithm, error) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return rsaAlgorithm(key)
	case *ecdsa.PublicKey:
		return ecdsaAlgorithm(key)
	default:
		return "", fmt.Errorf("%w: %T", ErrUnsupportedAlg, pubKey)
	}
}

func ecdsaAlgorithm(key *ecdsa.PublicKey) (jose.SignatureAlgorithm, error) {
	switch key.Params().BitSize {
	case 256: //nolint:mnd
		return jose.ES256, nil
	case 384: //nolint:mnd
		return jose.ES384, nil
	case 521: //nolint:mnd
		return jose.ES512, nil
	default:
		return "", fmt.Errorf("%w for ecdsa: %d", ErrUnsupportedKeySize, key.Params().BitSize)
	}
}

func rsaAlgorithm(key *rsa.PublicKey) (jose.SignatureAlgorithm, error) {
	keySize := key.Size() * 8 //nolint:mnd

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
