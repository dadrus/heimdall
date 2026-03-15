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

package keyregistry

import (
	"context"
	"crypto/x509"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
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

type registry struct {
	mut sync.RWMutex

	// Internal state used to calculate the keysSnapshot and the metricsState
	state map[string]KeyInfo

	// Immutable snapshot returned by Keys().
	keysSnapshot []jose.JSONWebKey

	// Prepared state for certificate-related metrics used during metrics gathering.
	metricsState map[certID]certEntry

	// The actual metric
	certExpiry metric.Float64ObservableGauge
}

func newRegistry(meter metric.Meter) (Registry, error) {
	certExpiry, err := meter.Float64ObservableGauge("certificate.expiry",
		metric.WithDescription("Number of seconds until certificate expires"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	reg := &registry{
		state:        make(map[string]KeyInfo, 10),
		metricsState: make(map[certID]certEntry, 10),
		certExpiry:   certExpiry,
	}

	if _, err = meter.RegisterCallback(reg.collect, certExpiry); err != nil {
		return nil, err
	}

	return reg, nil
}

func (r *registry) Keys() []jose.JSONWebKey {
	r.mut.RLock()
	keys := r.keysSnapshot
	r.mut.RUnlock()

	return keys
}

func (r *registry) Notify(ki KeyInfo) {
	r.mut.Lock()
	defer r.mut.Unlock()

	old := r.state[ki.KeyID]
	r.state[ki.KeyID] = ki

	r.updateMetricsData(old.CertChain, -1)
	r.updateMetricsData(ki.CertChain, 1)

	r.rebuildExportableKeys()
}

func (r *registry) updateMetricsData(chain []*x509.Certificate, delta int) {
	for _, cert := range chain {
		key := createCertID(cert)
		entry, exists := r.metricsState[key]
		entry.refCount += delta

		if entry.refCount <= 0 {
			delete(r.metricsState, key)

			continue
		}

		if !exists && delta > 0 {
			entry.notAfter = cert.NotAfter
			entry.attrs = buildAttributes(cert)
		}

		r.metricsState[key] = entry
	}
}

func createCertID(cert *x509.Certificate) certID {
	return certID{
		issuer: cert.Issuer.String(),
		serial: cert.SerialNumber.String(),
	}
}

func (r *registry) rebuildExportableKeys() {
	snapshot := make([]jose.JSONWebKey, 0, len(r.state))

	keys := slices.Collect(maps.Keys(r.state))
	slices.Sort(keys)

	for _, id := range keys {
		key := r.state[id]
		if !key.Exportable {
			continue
		}

		snapshot = append(snapshot, key.JWK())
	}

	r.keysSnapshot = snapshot
}

func (r *registry) collect(_ context.Context, observer metric.Observer) error {
	now := time.Now()

	r.mut.RLock()
	defer r.mut.RUnlock()

	for _, entry := range r.metricsState {
		observer.ObserveFloat64(
			r.certExpiry,
			entry.notAfter.Sub(now).Seconds(),
			metric.WithAttributeSet(entry.attrs),
		)
	}

	return nil
}

func buildAttributes(cert *x509.Certificate) attribute.Set {
	dnsNames := append([]string(nil), cert.DNSNames...)
	sort.Strings(dnsNames)

	return attribute.NewSet(
		certificateIssuerKey.String(cert.Issuer.String()),
		certificateSerialNumberKey.String(cert.SerialNumber.String()),
		certificateSubjectKey.String(cert.Subject.String()),
		certificateDNSNameKey.String(strings.Join(dnsNames, ",")),
	)
}
