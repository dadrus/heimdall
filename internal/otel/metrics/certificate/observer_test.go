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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func attributeValue(set attribute.Set, key attribute.Key) attribute.Value {
	if res, present := set.Value(key); present {
		return res
	}

	return attribute.Value{}
}

func dataPointForCert(cert *x509.Certificate, dps []metricdata.DataPoint[float64]) []metricdata.DataPoint[float64] {
	var data []metricdata.DataPoint[float64]

	for _, dp := range dps {
		if cert.Subject.String() == attributeValue(dp.Attributes, subjectAttrKey).AsString() {
			data = append(data, dp)
		}
	}

	return data
}

func checkMetric(t *testing.T, dp []metricdata.DataPoint[float64], service string, cert *x509.Certificate) {
	t.Helper()

	data := dataPointForCert(cert, dp)
	require.GreaterOrEqual(t, len(data), 1)

	names := make([]string, len(data))

	for idx, entry := range data {
		assert.LessOrEqual(t, entry.Value-time.Until(cert.NotAfter).Seconds(), 1.0)

		attributes := entry.Attributes
		require.Equal(t, 5, attributes.Len())
		assert.Equal(t, strings.Join(cert.DNSNames, ","), attributeValue(attributes, dnsNameAttrKey).AsString())
		assert.Equal(t, cert.Issuer.String(), attributeValue(attributes, issuerAttrKey).AsString())
		assert.Equal(t, cert.SerialNumber.String(), attributeValue(attributes, serialNrAttrKey).AsString())
		assert.Equal(t, cert.Subject.String(), attributeValue(attributes, subjectAttrKey).AsString())

		names[idx] = attributeValue(attributes, serviceAttrKey).AsString()
	}

	assert.Contains(t, names, service)
}

type testCertificateSupplier struct {
	name  string
	certs []*x509.Certificate
}

func (s *testCertificateSupplier) Name() string                      { return s.name }
func (s *testCertificateSupplier) Certificates() []*x509.Certificate { return s.certs }

func TestCertificateExpirationCollector(t *testing.T) {
	t.Parallel()

	// Root CA
	rootCA1, err := testsupport.NewRootCA("Test Root CA 1", time.Hour*24)
	require.NoError(t, err)

	// INT CAs
	intCA1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	intCA1Cert, err := rootCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test Int CA 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithIsCA(),
		testsupport.WithValidity(time.Now(), time.Hour*12),
		testsupport.WithSubjectPubKey(&intCA1PrivKey.PublicKey, x509.ECDSAWithSHA384))
	require.NoError(t, err)

	intCA1 := testsupport.NewCA(intCA1PrivKey, intCA1Cert)

	// EE CERTS
	ee1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	ee1cert, err := intCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour*1),
		testsupport.WithSubjectPubKey(&ee1PrivKey.PublicKey, x509.ECDSAWithSHA384))
	require.NoError(t, err)

	ee2PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	ee2cert, err := intCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 2",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now().Add(-time.Hour*1), time.Hour*2),
		testsupport.WithSubjectPubKey(&ee2PrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
	require.NoError(t, err)

	for _, tc := range []struct {
		uc        string
		suppliers []Supplier
		assert    func(t *testing.T, rm *metricdata.ResourceMetrics)
	}{
		{
			uc: "without suppliers",
			assert: func(t *testing.T, rm *metricdata.ResourceMetrics) {
				t.Helper()

				assert.Empty(t, rm.ScopeMetrics)
			},
		},
		{
			uc: "with single supplier providing only ee certificate",
			suppliers: []Supplier{
				&testCertificateSupplier{name: "test", certs: []*x509.Certificate{ee1cert}},
			},
			assert: func(t *testing.T, rm *metricdata.ResourceMetrics) {
				t.Helper()

				require.Len(t, rm.ScopeMetrics, 1)

				sm := rm.ScopeMetrics[0]
				require.Len(t, sm.Metrics, 1)

				metrics := sm.Metrics[0]
				assert.Equal(t, "certificate.expiry", metrics.Name)
				assert.Equal(t, "s", metrics.Unit)
				assert.Equal(t, "Number of seconds until certificate expires", metrics.Description)

				data := metrics.Data.(metricdata.Sum[float64]) // nolint: forcetypeassert
				assert.False(t, data.IsMonotonic)
				assert.Len(t, data.DataPoints, 1)

				checkMetric(t, data.DataPoints, "test", ee1cert)
			},
		},
		{
			uc: "with single supplier providing the entire chain",
			suppliers: []Supplier{
				&testCertificateSupplier{name: "test", certs: []*x509.Certificate{ee1cert, intCA1Cert, rootCA1.Certificate}},
			},
			assert: func(t *testing.T, rm *metricdata.ResourceMetrics) {
				t.Helper()

				require.Len(t, rm.ScopeMetrics, 1)

				sm := rm.ScopeMetrics[0]
				require.Len(t, sm.Metrics, 1)

				metrics := sm.Metrics[0]
				assert.Equal(t, "certificate.expiry", metrics.Name)
				assert.Equal(t, "s", metrics.Unit)
				assert.Equal(t, "Number of seconds until certificate expires", metrics.Description)

				data := metrics.Data.(metricdata.Sum[float64]) // nolint: forcetypeassert
				assert.False(t, data.IsMonotonic)
				assert.Len(t, data.DataPoints, 3)

				checkMetric(t, data.DataPoints, "test", rootCA1.Certificate)
				checkMetric(t, data.DataPoints, "test", intCA1Cert)
				checkMetric(t, data.DataPoints, "test", ee1cert)
			},
		},
		{
			uc: "with multiple suppliers providing the entire chain",
			suppliers: []Supplier{
				&testCertificateSupplier{name: "test-1", certs: []*x509.Certificate{ee1cert, intCA1Cert, rootCA1.Certificate}},
				&testCertificateSupplier{name: "test-2", certs: []*x509.Certificate{ee2cert, intCA1Cert, rootCA1.Certificate}},
			},
			assert: func(t *testing.T, rm *metricdata.ResourceMetrics) {
				t.Helper()

				require.Len(t, rm.ScopeMetrics, 1)

				sm := rm.ScopeMetrics[0]
				require.Len(t, sm.Metrics, 1)

				metrics := sm.Metrics[0]
				assert.Equal(t, "certificate.expiry", metrics.Name)
				assert.Equal(t, "s", metrics.Unit)
				assert.Equal(t, "Number of seconds until certificate expires", metrics.Description)

				data := metrics.Data.(metricdata.Sum[float64]) // nolint: forcetypeassert
				assert.False(t, data.IsMonotonic)
				assert.Len(t, data.DataPoints, 6)

				checkMetric(t, data.DataPoints, "test-1", rootCA1.Certificate)
				checkMetric(t, data.DataPoints, "test-1", intCA1Cert)
				checkMetric(t, data.DataPoints, "test-1", ee1cert)

				checkMetric(t, data.DataPoints, "test-2", rootCA1.Certificate)
				checkMetric(t, data.DataPoints, "test-2", intCA1Cert)
				checkMetric(t, data.DataPoints, "test-2", ee2cert)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			exp := metric.NewManualReader()

			otel.SetMeterProvider(metric.NewMeterProvider(
				metric.WithResource(resource.Default()),
				metric.WithReader(exp),
			))

			obs := NewObserver()
			for _, supplier := range tc.suppliers {
				obs.Add(supplier)
			}

			// WHEN
			err = obs.Start()

			// THEN
			require.NoError(t, err)

			var rm metricdata.ResourceMetrics
			err = exp.Collect(context.TODO(), &rm)

			require.NoError(t, err)

			tc.assert(t, &rm)
		})
	}
}
