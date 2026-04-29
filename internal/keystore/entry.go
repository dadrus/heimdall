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

package keystore

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/go-jose/go-jose/v4"

	"github.com/dadrus/heimdall/internal/x"
)

const (
	rsa2048 = 2048
	rsa3072 = 3072
	rsa4096 = 4096

	ecdsa256 = 256
	ecdsa384 = 384
	ecdsa512 = 521
)

type Entry struct {
	KeyID      string
	Alg        string
	KeySize    int
	PrivateKey crypto.Signer
	CertChain  []*x509.Certificate
}

func (e *Entry) JWK() jose.JSONWebKey {
	return jose.JSONWebKey{
		KeyID:     e.KeyID,
		Algorithm: string(joseAlgorithm(e.Alg, e.KeySize)),
		Key: x.IfThenElseExec(e.PrivateKey != nil,
			func() crypto.PublicKey { return e.PrivateKey.Public() },
			func() crypto.PublicKey { return e.CertChain[0].PublicKey },
		),
		Use:          "sig",
		Certificates: e.CertChain,
	}
}

func joseAlgorithm(alg string, keySize int) jose.SignatureAlgorithm {
	switch alg {
	case AlgRSA:
		return getRSAAlgorithm(keySize)
	case AlgECDSA:
		return getECDSAAlgorithm(keySize)
	default:
		panic("Unsupported algorithm: " + alg)
	}
}

func getECDSAAlgorithm(keySize int) jose.SignatureAlgorithm {
	switch keySize {
	case ecdsa256:
		return jose.ES256
	case ecdsa384:
		return jose.ES384
	case ecdsa512:
		return jose.ES512
	default:
		panic(fmt.Sprintf("unsupported ECDSA key size: %d", keySize))
	}
}

func getRSAAlgorithm(keySize int) jose.SignatureAlgorithm {
	switch keySize {
	case rsa2048:
		return jose.PS256
	case rsa3072:
		return jose.PS384
	case rsa4096:
		return jose.PS512
	default:
		panic(fmt.Sprintf("unsupported RSA key size: %d", keySize))
	}
}
