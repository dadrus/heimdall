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

package testsupport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"time"
)

type EndEntity struct {
	Certificate *x509.Certificate
	PrivKey     any
}

type CA struct {
	lastEECertSN int64
	PrivKey      *ecdsa.PrivateKey
	Certificate  *x509.Certificate
}

func NewCA(privKey *ecdsa.PrivateKey, cert *x509.Certificate) *CA {
	return &CA{
		lastEECertSN: 0,
		PrivKey:      privKey,
		Certificate:  cert,
	}
}

func NewRootCA(CN string, validity time.Duration) (*CA, error) { // nolint: gocritic
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	opts := []CertificateBuilderOption{
		WithValidity(time.Now(), validity),
		WithSerialNumber(big.NewInt(1)),
		WithSubject(pkix.Name{
			CommonName:   CN,
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		WithSubjectPubKey(&priv.PublicKey, x509.ECDSAWithSHA384),
		WithIsCA(),
		WithSelfSigned(),
		WithSignaturePrivKey(priv),
	}

	cb := NewCertificateBuilder(opts...)

	cert, err := cb.Build()
	if err != nil {
		return nil, err
	}

	return &CA{
		PrivKey:      priv,
		Certificate:  cert,
		lastEECertSN: 0,
	}, nil
}

func (ca *CA) IssueCertificate(opts ...CertificateBuilderOption) (*x509.Certificate, error) {
	options := slices.Clone(opts)
	options = append(options,
		WithSerialNumber(ca.nextSN()),
		WithIssuer(ca.PrivKey, ca.Certificate),
	)

	cb := NewCertificateBuilder(options...)

	return cb.Build()
}

func (ca *CA) nextSN() *big.Int {
	ca.lastEECertSN++

	return big.NewInt(ca.lastEECertSN)
}
