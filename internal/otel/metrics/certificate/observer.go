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

//go:generate mockery --name Observer --structname ObserverMock

type Observer interface {
	Add(sup Supplier)
	Start() error
}

type observer struct {
	meter     metric.Meter
	suppliers []Supplier
	mut       sync.RWMutex
}

func NewObserver() Observer {
	provider := otel.GetMeterProvider()

	return &observer{
		meter: provider.Meter(
			"github.com/dadrus/heimdall/internal/otel/metrics/certificate",
			metric.WithInstrumentationVersion(version.Version),
		),
	}
}

// Start initializes reporting of host metrics using the supplied config.
func (eo *observer) Start() error {
	expirationCounter, err := eo.meter.Float64ObservableUpDownCounter(
		"certificate.expiry",
		metric.WithDescription("Number of seconds until certificate expires"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return err
	}

	_, err = eo.meter.RegisterCallback(
		func(_ context.Context, observer metric.Observer) error {
			eo.mut.RLock()
			defer eo.mut.RUnlock()

			for _, sup := range eo.suppliers {
				certs := sup.Certificates()
				for _, cert := range certs {
					observer.ObserveFloat64(
						expirationCounter,
						time.Until(cert.NotAfter).Seconds(),
						metric.WithAttributes(
							serviceAttrKey.String(sup.Name()),
							issuerAttrKey.String(cert.Issuer.String()),
							serialNrAttrKey.String(cert.SerialNumber.String()),
							subjectAttrKey.String(cert.Subject.String()),
							dnsNameAttrKey.String(strings.Join(cert.DNSNames, ",")),
						),
					)
				}
			}

			return nil
		},
		expirationCounter,
	)

	return err
}

func (eo *observer) Add(sup Supplier) {
	eo.mut.Lock()
	defer eo.mut.Unlock()

	eo.suppliers = append(eo.suppliers, sup)
}
