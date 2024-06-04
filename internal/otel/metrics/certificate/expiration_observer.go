// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package certificate

import (
	"context"
	"crypto/x509"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/dadrus/heimdall/version"
)

const (
	serviceAttrKey  = attribute.Key("service")
	issuerAttrKey   = attribute.Key("issuer")
	serialNrAttrKey = attribute.Key("serial_nr")
	subjectAttrKey  = attribute.Key("subject")
	dnsNameAttrKey  = attribute.Key("dns_names")
)

type service struct {
	name            string
	getCertificates func() []*x509.Certificate
}

type expirationObserver struct {
	meter              metric.Meter
	services           []*service
	monitorEECertsOnly bool
}

// Start initializes reporting of host metrics using the supplied config.
func Start(opts ...Option) error {
	conf := newConfig(opts...)
	if conf.provider == nil {
		conf.provider = otel.GetMeterProvider()
	}

	eo := &expirationObserver{
		meter: conf.provider.Meter(
			"github.com/dadrus/heimdall/internal/otel/metrics/certificate",
			metric.WithInstrumentationVersion(version.Version),
		),
		services:           conf.services,
		monitorEECertsOnly: conf.monitorEECertsOnly,
	}

	return eo.register()
}

func (eo *expirationObserver) register() error {
	var (
		err               error
		expirationCounter metric.Float64ObservableUpDownCounter

		// lock prevents a race between batch observer and instrument registration.
		lock sync.Mutex
	)

	lock.Lock()
	defer lock.Unlock()

	expirationCounter, err = eo.meter.Float64ObservableUpDownCounter(
		"certificate.expiry",
		metric.WithDescription("Number of seconds until certificate expires"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return err
	}

	_, err = eo.meter.RegisterCallback(
		func(_ context.Context, observer metric.Observer) error {
			lock.Lock()
			defer lock.Unlock()

			for _, srv := range eo.services {
				certs := srv.getCertificates()
				if eo.monitorEECertsOnly {
					eo.observeCertificate(observer, expirationCounter, certs[0], srv.name)
				} else {
					for _, cert := range certs {
						eo.observeCertificate(observer, expirationCounter, cert, srv.name)
					}
				}
			}

			return nil
		},
		expirationCounter,
	)

	return err
}

func (eo *expirationObserver) observeCertificate(
	observer metric.Observer,
	counter metric.Float64ObservableUpDownCounter,
	cert *x509.Certificate,
	srvName string,
) {
	observer.ObserveFloat64(
		counter,
		time.Until(cert.NotAfter).Seconds(),
		metric.WithAttributes(
			serviceAttrKey.String(srvName),
			issuerAttrKey.String(cert.Issuer.String()),
			serialNrAttrKey.String(cert.SerialNumber.String()),
			subjectAttrKey.String(cert.Subject.String()),
			dnsNameAttrKey.String(strings.Join(cert.DNSNames, ",")),
		),
	)
}
