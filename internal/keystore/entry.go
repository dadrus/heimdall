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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

const (
	rsa2048 = 2048
	rsa3072 = 3072
	rsa4096 = 4096

	ecdsa256 = 256
	ecdsa384 = 384
	ecdsa512 = 521
)

var ErrNoCertificatePresent = errors.New("no certificate present")

type Entry struct {
	KeyID      string
	Alg        string
	KeySize    int
	PrivateKey crypto.Signer
	CertChain  []*x509.Certificate
}

func (e *Entry) JWK() jose.JSONWebKey {
	return jose.JSONWebKey{
		KeyID:        e.KeyID,
		Algorithm:    string(e.JOSEAlgorithm()),
		Key:          e.PrivateKey.Public(),
		Use:          "sig",
		Certificates: e.CertChain,
	}
}

func (e *Entry) JOSEAlgorithm() jose.SignatureAlgorithm {
	switch e.Alg {
	case AlgRSA:
		return getRSAAlgorithm(e.KeySize)
	case AlgECDSA:
		return getECDSAAlgorithm(e.KeySize)
	default:
		panic("Unsupported algorithm: " + e.Alg)
	}
}

func (e *Entry) TLSCertificate() (tls.Certificate, error) {
	if len(e.CertChain) == 0 {
		return tls.Certificate{}, ErrNoCertificatePresent
	}

	cert := tls.Certificate{
		PrivateKey: e.PrivateKey,
		Leaf:       e.CertChain[0],
	}

	for _, cer := range e.CertChain {
		cert.Certificate = append(cert.Certificate, cer.Raw)
	}

	return cert, nil
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
