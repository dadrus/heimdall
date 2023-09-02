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
	"crypto/rand"
	// used for subject key id generation
	// nolint: gosec
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type CertificateBuilderOption func(*CertificateBuilder)

type CertificateBuilder struct {
	tmpl                  *x509.Certificate
	subjectPubKey         any
	selfSigned            bool
	privKey               any
	issuerCert            *x509.Certificate
	generateKeyIdentifier bool
}

func WithValidity(notBefore time.Time, duration time.Duration) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.NotBefore = notBefore
		builder.tmpl.NotAfter = notBefore.Add(duration)
	}
}

func WithSerialNumber(SN *big.Int) CertificateBuilderOption { // nolint: gocritic
	return func(builder *CertificateBuilder) {
		builder.tmpl.SerialNumber = SN
	}
}

func WithSubject(name pkix.Name) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.Subject = name
	}
}

func WithKeyUsage(keyUsage x509.KeyUsage) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.KeyUsage = keyUsage
	}
}

func WithSubjectPubKey(key any, alg x509.SignatureAlgorithm) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.SignatureAlgorithm = alg
		builder.subjectPubKey = key
	}
}

func WithSelfSigned() CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.selfSigned = true
	}
}

func WithExtension(extension pkix.Extension) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.Extensions = append(builder.tmpl.Extensions, extension)
	}
}

func WithExtraExtension(extension pkix.Extension) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.ExtraExtensions = append(builder.tmpl.ExtraExtensions, extension)
	}
}

func WithExtendedKeyUsage(usage x509.ExtKeyUsage) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.ExtKeyUsage = append(builder.tmpl.ExtKeyUsage, usage)
	}
}

func WithIsCA() CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.IsCA = true
		builder.tmpl.BasicConstraintsValid = true
	}
}

func WithSignaturePrivKey(key any) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.privKey = key
	}
}

func WithIssuer(key any, cert *x509.Certificate) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.privKey = key
		builder.issuerCert = cert
	}
}

func WithSubjectKeyID(skid []byte) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.SubjectKeyId = skid
	}
}

func WithDNSNames(names []string) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.DNSNames = names
	}
}

func WithIPAddresses(addresses []net.IP) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.IPAddresses = addresses
	}
}

func WithEMailAddresses(addresses []string) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.EmailAddresses = addresses
	}
}

func WithURIs(uris []*url.URL) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.URIs = uris
	}
}

func WithGeneratedSubjectKeyID() CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.generateKeyIdentifier = true
	}
}

func NewCertificateBuilder(opts ...CertificateBuilderOption) *CertificateBuilder {
	builder := &CertificateBuilder{
		tmpl: &x509.Certificate{},
	}

	for _, opt := range opts {
		opt(builder)
	}

	if builder.tmpl.IsCA {
		builder.tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	return builder
}

func (cb *CertificateBuilder) Build() (*x509.Certificate, error) {
	var err error

	// generate public key identifier
	if cb.generateKeyIdentifier {
		if cb.tmpl.SubjectKeyId, err = subjectKeyID(cb.subjectPubKey); err != nil {
			return nil, err
		}
	}

	raw, err := x509.CreateCertificate(
		rand.Reader,
		cb.tmpl,
		x.IfThenElse(cb.selfSigned, cb.tmpl, cb.issuerCert),
		cb.subjectPubKey,
		cb.privKey,
	)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(raw)
}

func subjectKeyID(pubKey any) ([]byte, error) {
	// Subject Key Identifier support
	// https://www.ietf.org/rfc/rfc3280.txt (section 4.2.1.2)
	marshaledKey, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to calculated subject public key id").CausedBy(err)
	}

	subjKeyID := sha1.Sum(marshaledKey) // nolint: gosec

	return subjKeyID[:], nil
}
