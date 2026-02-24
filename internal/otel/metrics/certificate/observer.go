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

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/dadrus/heimdall/internal/otel/semconv"
)

type Observer interface {
	Add(sup Supplier)
}

type observer struct {
	suppliers []Supplier
	mut       sync.RWMutex

	ce semconv.CertificateExpiry
}

func NewObserver(meter metric.Meter) (Observer, error) {
	ce, err := semconv.NewCertificateExpiry(meter)
	if err != nil {
		return nil, err
	}

	obs := &observer{ce: ce}

	if _, err = meter.RegisterCallback(obs.collectMetrics, ce.Inst()); err != nil {
		return nil, err
	}

	return obs, nil
}

func (eo *observer) Add(sup Supplier) {
	eo.mut.Lock()
	defer eo.mut.Unlock()

	eo.suppliers = append(eo.suppliers, sup)
}

func (eo *observer) collectMetrics(_ context.Context, observer metric.Observer) error {
	eo.mut.RLock()
	defer eo.mut.RUnlock()

	for _, sup := range eo.suppliers {
		certs := sup.Certificates()
		for _, cert := range certs {
			eo.ce.Observe(
				observer,
				time.Until(cert.NotAfter).Seconds(),
				attribute.NewSet(
					eo.ce.AttrService(sup.Name()),
					eo.ce.AttrIssuer(cert.Issuer.String()),
					eo.ce.AttrSerialNumber(cert.SerialNumber.String()),
					eo.ce.AttrSubject(cert.Subject.String()),
					eo.ce.AttrDNSNames(strings.Join(cert.DNSNames, ",")),
				),
			)
		}
	}

	return nil
}
