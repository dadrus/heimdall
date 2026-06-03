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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	x509pkix "crypto/x509/pkix"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"

	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCertificateMeterTrack(t *testing.T) {
	t.Parallel()

	rootCA, err := testsupport.NewRootCA("Test Root CA", 24*time.Hour)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, metrics *certificateMeter)
		assert func(t *testing.T, points []metricdata.DataPoint[float64])
	}{
		"ignores non asymmetric key secrets": {
			setup: func(t *testing.T, metrics *certificateMeter) {
				t.Helper()

				metrics.Track(secrettypes.NewStringSecret("foo", "bar"))
			},
			assert: func(t *testing.T, points []metricdata.DataPoint[float64]) {
				t.Helper()

				require.Empty(t, points)
			},
		},
		"ignores asymmetric key secret without certificates": {
			setup: func(t *testing.T, metrics *certificateMeter) {
				t.Helper()

				privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)

				metrics.Track(secrettypes.NewAsymmetricKeySecret("key-id", "key-id", privateKey, nil))
			},
			assert: func(t *testing.T, points []metricdata.DataPoint[float64]) {
				t.Helper()

				require.Empty(t, points)
			},
		},
		"observes certificates from asymmetric key secret": {
			setup: func(t *testing.T, metrics *certificateMeter) {
				t.Helper()

				privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)

				leafCert, err := rootCA.IssueCertificate(
					testsupport.WithSubject(x509pkix.Name{
						CommonName:   "example.com",
						Organization: []string{"Heimdall"},
						Country:      []string{"EU"},
					}),
					testsupport.WithValidity(time.Now(), time.Hour),
					testsupport.WithSubjectPubKey(&privateKey.PublicKey, x509.ECDSAWithSHA384),
					testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
					testsupport.WithDNSNames([]string{"www.example.com", "example.com"}),
					testsupport.WithGeneratedSubjectKeyID(),
				)
				require.NoError(t, err)

				metrics.Track(secrettypes.NewAsymmetricKeySecret(
					"key-id",
					"key-id",
					privateKey,
					[]*x509.Certificate{leafCert, rootCA.Certificate},
				))
			},
			assert: func(t *testing.T, points []metricdata.DataPoint[float64]) {
				t.Helper()

				require.Len(t, points, 2)

				assertCertificateDataPoint(
					t,
					points,
					"CN=example.com,O=Heimdall,C=EU",
					"example.com,www.example.com",
				)
				assertCertificateDataPoint(
					t,
					points,
					rootCA.Certificate.Subject.String(),
					"",
				)
			},
		},
		"deduplicates observed certificates and keeps them until all observations are forgotten": {
			setup: func(t *testing.T, metrics *certificateMeter) {
				t.Helper()

				privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)

				cert, err := rootCA.IssueCertificate(
					testsupport.WithSubject(x509pkix.Name{CommonName: "example.com"}),
					testsupport.WithValidity(time.Now(), time.Hour),
					testsupport.WithSubjectPubKey(&privateKey.PublicKey, x509.ECDSAWithSHA384),
					testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
					testsupport.WithDNSNames([]string{"example.com"}),
					testsupport.WithGeneratedSubjectKeyID(),
				)
				require.NoError(t, err)

				secret := secrettypes.NewAsymmetricKeySecret(
					"key-id",
					"key-id",
					privateKey,
					[]*x509.Certificate{cert},
				)

				metrics.Track(secret)
				metrics.Track(secret)
				metrics.Untrack(secret)
			},
			assert: func(t *testing.T, points []metricdata.DataPoint[float64]) {
				t.Helper()

				require.Len(t, points, 1)
				assertCertificateDataPoint(t, points, "CN=example.com", "example.com")
			},
		},
		"removes certificate after last observation is forgotten": {
			setup: func(t *testing.T, metrics *certificateMeter) {
				t.Helper()

				privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)

				cert, err := rootCA.IssueCertificate(
					testsupport.WithSubject(x509pkix.Name{CommonName: "example.com"}),
					testsupport.WithValidity(time.Now(), time.Hour),
					testsupport.WithSubjectPubKey(&privateKey.PublicKey, x509.ECDSAWithSHA384),
					testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
					testsupport.WithDNSNames([]string{"example.com"}),
					testsupport.WithGeneratedSubjectKeyID(),
				)
				require.NoError(t, err)

				secret := secrettypes.NewAsymmetricKeySecret(
					"key-id",
					"key-id",
					privateKey,
					[]*x509.Certificate{cert},
				)

				metrics.Track(secret)
				metrics.Untrack(secret)
			},
			assert: func(t *testing.T, points []metricdata.DataPoint[float64]) {
				t.Helper()

				require.Empty(t, points)
			},
		},
		"forgetting an unknown certificate is ignored": {
			setup: func(t *testing.T, metrics *certificateMeter) {
				t.Helper()

				privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)

				knownCert, err := rootCA.IssueCertificate(
					testsupport.WithSubject(x509pkix.Name{CommonName: "known.example.com"}),
					testsupport.WithValidity(time.Now(), time.Hour),
					testsupport.WithSubjectPubKey(&privateKey.PublicKey, x509.ECDSAWithSHA384),
					testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
					testsupport.WithDNSNames([]string{"known.example.com"}),
					testsupport.WithGeneratedSubjectKeyID(),
				)
				require.NoError(t, err)

				unknownCert, err := rootCA.IssueCertificate(
					testsupport.WithSubject(x509pkix.Name{CommonName: "unknown.example.com"}),
					testsupport.WithValidity(time.Now(), time.Hour),
					testsupport.WithSubjectPubKey(&privateKey.PublicKey, x509.ECDSAWithSHA384),
					testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
					testsupport.WithDNSNames([]string{"unknown.example.com"}),
					testsupport.WithGeneratedSubjectKeyID(),
				)
				require.NoError(t, err)

				knownSecret := secrettypes.NewAsymmetricKeySecret(
					"known",
					"known",
					privateKey,
					[]*x509.Certificate{knownCert},
				)
				unknownSecret := secrettypes.NewAsymmetricKeySecret(
					"unknown",
					"unknown",
					privateKey,
					[]*x509.Certificate{unknownCert},
				)

				metrics.Track(knownSecret)
				metrics.Untrack(unknownSecret)
			},
			assert: func(t *testing.T, points []metricdata.DataPoint[float64]) {
				t.Helper()

				require.Len(t, points, 1)
				assertCertificateDataPoint(t, points, "CN=known.example.com", "known.example.com")
			},
		},
		"replaces rotated certificate when old secret is forgotten and new secret is observed": {
			setup: func(t *testing.T, metrics *certificateMeter) {
				t.Helper()

				privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)

				oldCert, err := rootCA.IssueCertificate(
					testsupport.WithSubject(x509pkix.Name{CommonName: "old.example.com"}),
					testsupport.WithValidity(time.Now(), time.Hour),
					testsupport.WithSubjectPubKey(&privateKey.PublicKey, x509.ECDSAWithSHA384),
					testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
					testsupport.WithDNSNames([]string{"old.example.com"}),
					testsupport.WithGeneratedSubjectKeyID(),
				)
				require.NoError(t, err)

				newCert, err := rootCA.IssueCertificate(
					testsupport.WithSubject(x509pkix.Name{CommonName: "new.example.com"}),
					testsupport.WithValidity(time.Now(), 2*time.Hour),
					testsupport.WithSubjectPubKey(&privateKey.PublicKey, x509.ECDSAWithSHA384),
					testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
					testsupport.WithDNSNames([]string{"new.example.com"}),
					testsupport.WithGeneratedSubjectKeyID(),
				)
				require.NoError(t, err)

				oldSecret := secrettypes.NewAsymmetricKeySecret(
					"key-id",
					"key-id",
					privateKey,
					[]*x509.Certificate{oldCert},
				)
				newSecret := secrettypes.NewAsymmetricKeySecret(
					"key-id",
					"key-id",
					privateKey,
					[]*x509.Certificate{newCert},
				)

				metrics.Track(oldSecret)
				metrics.Untrack(oldSecret)
				metrics.Track(newSecret)
			},
			assert: func(t *testing.T, points []metricdata.DataPoint[float64]) {
				t.Helper()

				require.Len(t, points, 1)
				assertCertificateDataPoint(t, points, "CN=new.example.com", "new.example.com")
				assertNoCertificateDataPoint(t, points, "CN=old.example.com")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			reader := metric.NewManualReader()
			mp := metric.NewMeterProvider(
				metric.WithResource(resource.Default()),
				metric.WithReader(reader),
			)

			metrics, err := NewCertificateMeter(mp.Meter("test"))
			require.NoError(t, err)

			tc.setup(t, metrics)

			points := collectCertificateDataPoints(t, reader)

			tc.assert(t, points)
		})
	}
}

func TestCertificateMeterTrackSortsDNSNames(t *testing.T) {
	t.Parallel()

	rootCA, err := testsupport.NewRootCA("Test Root CA", 24*time.Hour)
	require.NoError(t, err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cert, err := rootCA.IssueCertificate(
		testsupport.WithSubject(x509pkix.Name{CommonName: "example.com"}),
		testsupport.WithValidity(time.Now(), time.Hour),
		testsupport.WithSubjectPubKey(&privateKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
		testsupport.WithDNSNames([]string{"www.example.com", "api.example.com", "example.com"}),
		testsupport.WithGeneratedSubjectKeyID(),
	)
	require.NoError(t, err)

	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(
		metric.WithResource(resource.Default()),
		metric.WithReader(reader),
	)

	metrics, err := NewCertificateMeter(mp.Meter("test"))
	require.NoError(t, err)

	metrics.Track(secrettypes.NewAsymmetricKeySecret(
		"key-id",
		"key-id",
		privateKey,
		[]*x509.Certificate{cert},
	))

	points := collectCertificateDataPoints(t, reader)

	require.Len(t, points, 1)
	assertCertificateDataPoint(t, points, "CN=example.com", "api.example.com,example.com,www.example.com")
}

func collectCertificateDataPoints(
	t *testing.T,
	reader *metric.ManualReader,
) []metricdata.DataPoint[float64] {
	t.Helper()

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &rm))

	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "certificate.expiry" {
				continue
			}

			data, ok := m.Data.(metricdata.Gauge[float64])
			require.True(t, ok)

			return data.DataPoints
		}
	}

	return nil
}

func assertCertificateDataPoint(
	t *testing.T,
	points []metricdata.DataPoint[float64],
	subject string,
	dnsNames string,
) {
	t.Helper()

	point := findCertificateDataPoint(t, points, subject)

	assert.Greater(t, point.Value, float64(0))

	val, present := point.Attributes.Value(certificateSubjectKey)
	require.True(t, present)
	assert.Equal(t, subject, val.AsString())

	val, present = point.Attributes.Value(certificateDNSNameKey)
	require.True(t, present)
	assert.Equal(t, dnsNames, val.AsString())

	val, present = point.Attributes.Value(certificateIssuerKey)
	require.True(t, present)
	assert.NotEmpty(t, val.AsString())

	val, present = point.Attributes.Value(certificateSerialNumberKey)
	require.True(t, present)
	assert.NotEmpty(t, val.AsString())
}

func assertNoCertificateDataPoint(
	t *testing.T,
	points []metricdata.DataPoint[float64],
	subject string,
) {
	t.Helper()

	for _, point := range points {
		val, present := point.Attributes.Value(certificateSubjectKey)
		if present && val.AsString() == subject {
			require.Failf(t, "certificate data point found", "subject %s", subject)
		}
	}
}

func findCertificateDataPoint(
	t *testing.T,
	points []metricdata.DataPoint[float64],
	subject string,
) metricdata.DataPoint[float64] {
	t.Helper()

	for _, point := range points {
		val, present := point.Attributes.Value(certificateSubjectKey)
		if present && val.AsString() == subject {
			return point
		}
	}

	require.Failf(t, "certificate data point not found", "subject %s", subject)

	return metricdata.DataPoint[float64]{}
}
