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

package pkix

import (
	"crypto/x509"
	"errors"
	"time"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrCertificateValidation = errors.New("certificate validation error")
	ErrMissingKeyUsage       = errors.New("missing key usage")
)

type keyUsageCheck func(setUsage x509.KeyUsage) error

type options struct {
	verifyOpts     x509.VerifyOptions
	keyUsageChecks []keyUsageCheck
	rootCAs        []*x509.Certificate
}

func (o options) checkKeyUsage(cert *x509.Certificate) error {
	for _, check := range o.keyUsageChecks {
		if err := check(cert.KeyUsage); err != nil {
			return err
		}
	}

	return nil
}

type ValidationOption func(opts *options) error

func WithDNSName(dnsName string) ValidationOption {
	return func(opts *options) error {
		opts.verifyOpts.DNSName = dnsName

		return nil
	}
}

func WithIntermediateCACertificates(certs []*x509.Certificate) ValidationOption {
	return func(opts *options) error {
		for _, cert := range certs {
			opts.verifyOpts.Intermediates.AddCert(cert)
		}

		return nil
	}
}

func WithRootCACertificates(certs []*x509.Certificate) ValidationOption {
	return func(opts *options) error {
		opts.rootCAs = append(opts.rootCAs, certs...)

		return nil
	}
}

func WithSystemTrustStore() ValidationOption {
	return func(opts *options) error {
		rootPool, err := x509.SystemCertPool()
		if err != nil {
			return err
		}

		opts.verifyOpts.Roots = rootPool

		return nil
	}
}

func WithCurrentTime(time time.Time) ValidationOption {
	return func(opts *options) error {
		opts.verifyOpts.CurrentTime = time

		return nil
	}
}

func WithKeyUsage(usage x509.KeyUsage) ValidationOption {
	return func(opts *options) error {
		opts.keyUsageChecks = append(opts.keyUsageChecks, func(setUsage x509.KeyUsage) error {
			if setUsage&usage != usage {
				return errorchain.NewWithMessage(ErrMissingKeyUsage, KeyUsage(usage).String())
			}

			return nil
		})

		return nil
	}
}

func WithExtendedKeyUsage(usage x509.ExtKeyUsage) ValidationOption {
	return func(opts *options) error {
		opts.verifyOpts.KeyUsages = append(opts.verifyOpts.KeyUsages, usage)

		return nil
	}
}

func ValidateCertificate(cert *x509.Certificate, opts ...ValidationOption) error {
	validationOpts := &options{
		verifyOpts: x509.VerifyOptions{
			Intermediates: x509.NewCertPool(),
		},
	}

	for _, opt := range opts {
		if err := opt(validationOpts); err != nil {
			return errorchain.NewWithMessagef(ErrCertificateValidation,
				"for certificate with DN='%s' and SN=%s", cert.Subject.String(), cert.SerialNumber.String()).
				CausedBy(err)
		}
	}

	if len(validationOpts.verifyOpts.KeyUsages) == 0 {
		validationOpts.verifyOpts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}

	if len(validationOpts.rootCAs) != 0 && validationOpts.verifyOpts.Roots == nil {
		validationOpts.verifyOpts.Roots = x509.NewCertPool()
	}

	for _, cert := range validationOpts.rootCAs {
		validationOpts.verifyOpts.Roots.AddCert(cert)
	}

	if _, err := cert.Verify(validationOpts.verifyOpts); err != nil {
		return errorchain.NewWithMessagef(ErrCertificateValidation,
			"for certificate with DN='%s' and SN=%s", cert.Subject.String(), cert.SerialNumber.String()).
			CausedBy(err)
	}

	if err := validationOpts.checkKeyUsage(cert); err != nil {
		return errorchain.NewWithMessagef(ErrCertificateValidation,
			"for certificate with DN='%s' and SN=%s", cert.Subject.String(), cert.SerialNumber.String()).
			CausedBy(err)
	}

	return nil
}
