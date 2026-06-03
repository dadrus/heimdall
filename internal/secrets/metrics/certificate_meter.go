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

package metrics

import (
	"context"
	"crypto/x509"
	"sort"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/dadrus/heimdall/internal/pipeline"
	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

const (
	certificateIssuerKey       = attribute.Key("issuer")
	certificateSerialNumberKey = attribute.Key("serial_nr")
	certificateSubjectKey      = attribute.Key("subject")
	certificateDNSNameKey      = attribute.Key("dns_names")
)

type certID struct {
	issuer string
	serial string
}

type certEntry struct {
	refCount int
	notAfter time.Time
	attrs    attribute.Set
}

type certificateMeter struct {
	mut sync.RWMutex

	certs map[certID]certEntry

	certExpiry metric.Float64ObservableGauge
}

func NewCertificateMeter(meter metric.Meter) (*certificateMeter, error) {
	certExpiry, err := meter.Float64ObservableGauge("certificate.expiry",
		metric.WithDescription("Number of seconds until certificate expires"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrInternal,
			"failed creating certificate.expiry gauge",
		).CausedBy(err)
	}

	metrics := &certificateMeter{
		certs:      make(map[certID]certEntry, 10),
		certExpiry: certExpiry,
	}

	if _, err = meter.RegisterCallback(metrics.collect, certExpiry); err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrInternal,
			"failed registering callback for certificate metrics collection",
		).CausedBy(err)
	}

	return metrics, nil
}

func (m *certificateMeter) Track(secret secrettypes.Secret) {
	asymmetricKey, ok := secret.(secrettypes.AsymmetricKeySecret)
	if !ok {
		return
	}

	m.mut.Lock()
	defer m.mut.Unlock()

	for _, cert := range asymmetricKey.CertChain() {
		if cert == nil {
			continue
		}

		id := createCertID(cert)
		entry := m.certs[id]
		entry.refCount++

		if entry.refCount == 1 {
			entry.notAfter = cert.NotAfter
			entry.attrs = buildCertificateAttributes(cert)
		}

		m.certs[id] = entry
	}
}

func (m *certificateMeter) Untrack(secret secrettypes.Secret) {
	asymmetricKey, ok := secret.(secrettypes.AsymmetricKeySecret)
	if !ok {
		return
	}

	m.mut.Lock()
	defer m.mut.Unlock()

	for _, cert := range asymmetricKey.CertChain() {
		if cert == nil {
			continue
		}

		id := createCertID(cert)

		entry, ok := m.certs[id]
		if !ok {
			continue
		}

		entry.refCount--
		if entry.refCount <= 0 {
			delete(m.certs, id)

			continue
		}

		m.certs[id] = entry
	}
}

func (m *certificateMeter) collect(_ context.Context, observer metric.Observer) error {
	now := time.Now()

	m.mut.RLock()
	defer m.mut.RUnlock()

	for _, entry := range m.certs {
		observer.ObserveFloat64(
			m.certExpiry,
			entry.notAfter.Sub(now).Seconds(),
			metric.WithAttributeSet(entry.attrs),
		)
	}

	return nil
}

func createCertID(cert *x509.Certificate) certID {
	return certID{
		issuer: cert.Issuer.String(),
		serial: cert.SerialNumber.String(),
	}
}

func buildCertificateAttributes(cert *x509.Certificate) attribute.Set {
	dnsNames := append([]string(nil), cert.DNSNames...)
	sort.Strings(dnsNames)

	return attribute.NewSet(
		certificateIssuerKey.String(cert.Issuer.String()),
		certificateSerialNumberKey.String(cert.SerialNumber.String()),
		certificateSubjectKey.String(cert.Subject.String()),
		certificateDNSNameKey.String(strings.Join(dnsNames, ",")),
	)
}
