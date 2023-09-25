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

package prometheus

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func checkMetric(t *testing.T, metric *io_prometheus_client.Metric, service string, cert *x509.Certificate) {
	t.Helper()

	assert.LessOrEqual(t, metric.GetGauge().GetValue()-time.Until(cert.NotAfter).Seconds(), 1.0)

	labels := metric.GetLabel()
	require.Len(t, labels, 5)
	assert.Equal(t, "dns_names", labels[0].GetName())
	assert.Equal(t, strings.Join(cert.DNSNames, ","), labels[0].GetValue())
	assert.Equal(t, "issuer", labels[1].GetName())
	assert.Equal(t, cert.Issuer.String(), labels[1].GetValue())
	assert.Equal(t, "serial_nr", labels[2].GetName())
	assert.Equal(t, cert.SerialNumber.String(), labels[2].GetValue())
	assert.Equal(t, "service", labels[3].GetName())
	assert.Equal(t, service, labels[3].GetValue())
	assert.Equal(t, "subject", labels[4].GetName())
	assert.Equal(t, cert.Subject.String(), labels[4].GetValue())
}
