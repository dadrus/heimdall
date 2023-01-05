package prometheus

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCertificateExpirationCollector(t *testing.T) { //nolint:maintidx
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

	ksPEMBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(ee2PrivKey),
		pemx.WithX509Certificate(ee2cert),
		pemx.WithX509Certificate(intCA1Cert),
		pemx.WithX509Certificate(rootCA1.Certificate),
		pemx.WithECDSAPrivateKey(ee1PrivKey, pemx.WithHeader("X-Key-ID", "key1")),
		pemx.WithX509Certificate(ee1cert),
		pemx.WithX509Certificate(intCA1Cert),
		pemx.WithX509Certificate(rootCA1.Certificate),
	)
	require.NoError(t, err)

	ks, err := keystore.NewKeyStoreFromPEMBytes(ksPEMBytes, "")
	require.NoError(t, err)

	for _, tc := range []struct {
		uc        string
		collector prometheus.Collector
		assert    func(t *testing.T, err error, result []*io_prometheus_client.MetricFamily)
	}{
		{
			uc: "with nil key store",
			collector: NewCertificateExpirationCollector(
				WithServiceKeyStore("foo", nil, WithKeyID("key1")),
				WithEndEntityMonitoringOnly(false)),
			assert: func(t *testing.T, err error, result []*io_prometheus_client.MetricFamily) {
				t.Helper()

				require.NoError(t, err)
				assert.Empty(t, result)
			},
		},
		{
			uc: "with unknown key id",
			collector: NewCertificateExpirationCollector(
				WithServiceKeyStore("foo", ks, WithKeyID("foo")),
				WithEndEntityMonitoringOnly(false)),
			assert: func(t *testing.T, err error, result []*io_prometheus_client.MetricFamily) {
				t.Helper()

				require.NoError(t, err)
				assert.Empty(t, result)
			},
		},
		{
			uc: "for single service from single certificate",
			collector: NewCertificateExpirationCollector(
				WithServiceCertificates("foo", []*x509.Certificate{rootCA1.Certificate})),
			assert: func(t *testing.T, err error, result []*io_prometheus_client.MetricFamily) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, result, 1)

				metric := result[0]
				assert.Equal(t, "certificate_expiry_seconds", metric.GetName())
				assert.Equal(t, "Number of seconds until certificate expires", metric.GetHelp())
				assert.Equal(t, io_prometheus_client.MetricType_GAUGE, metric.GetType())

				values := metric.GetMetric()
				require.Len(t, values, 1)
				assert.LessOrEqual(t, 86400.0-values[0].GetGauge().GetValue(), 1.0)

				labels := values[0].GetLabel()
				require.Len(t, labels, 5)
				assert.Equal(t, "dns_names", labels[0].GetName())
				assert.Empty(t, labels[0].GetValue())
				assert.Equal(t, "issuer", labels[1].GetName())
				assert.Equal(t, "CN=Test Root CA 1,O=Test,C=EU", labels[1].GetValue())
				assert.Equal(t, "serial_nr", labels[2].GetName())
				assert.Equal(t, "1", labels[2].GetValue())
				assert.Equal(t, "service", labels[3].GetName())
				assert.Equal(t, "foo", labels[3].GetValue())
				assert.Equal(t, "subject", labels[4].GetName())
				assert.Equal(t, "CN=Test Root CA 1,O=Test,C=EU", labels[4].GetValue())
			},
		},
		{
			uc: "for single service for all certificates from existing key store entry specified by key id",
			collector: NewCertificateExpirationCollector(
				WithServiceKeyStore("foo", ks, WithKeyID("key1")),
				WithEndEntityMonitoringOnly(false)),
			assert: func(t *testing.T, err error, result []*io_prometheus_client.MetricFamily) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, result, 1)

				metric := result[0]
				assert.Equal(t, "certificate_expiry_seconds", metric.GetName())
				assert.Equal(t, "Number of seconds until certificate expires", metric.GetHelp())
				assert.Equal(t, io_prometheus_client.MetricType_GAUGE, metric.GetType())

				values := metric.GetMetric()
				require.Len(t, values, 3)

				// first certificate in the chain
				value := values[0]
				assert.LessOrEqual(t, 3600.0-value.GetGauge().GetValue(), 1.0)

				labels := value.GetLabel()
				require.Len(t, labels, 5)
				assert.Equal(t, "dns_names", labels[0].GetName())
				assert.Empty(t, labels[0].GetValue())
				assert.Equal(t, "issuer", labels[1].GetName())
				assert.Equal(t, "CN=Test Int CA 1,O=Test,C=EU", labels[1].GetValue())
				assert.Equal(t, "serial_nr", labels[2].GetName())
				assert.Equal(t, "1", labels[2].GetValue())
				assert.Equal(t, "service", labels[3].GetName())
				assert.Equal(t, "foo", labels[3].GetValue())
				assert.Equal(t, "subject", labels[4].GetName())
				assert.Equal(t, "CN=Test EE 1,O=Test,C=EU", labels[4].GetValue())

				// second certificate in the chain
				value = values[1]
				assert.LessOrEqual(t, 43200.0-value.GetGauge().GetValue(), 1.0)

				labels = value.GetLabel()
				require.Len(t, labels, 5)
				assert.Equal(t, "dns_names", labels[0].GetName())
				assert.Empty(t, labels[0].GetValue())
				assert.Equal(t, "issuer", labels[1].GetName())
				assert.Equal(t, "CN=Test Root CA 1,O=Test,C=EU", labels[1].GetValue())
				assert.Equal(t, "serial_nr", labels[2].GetName())
				assert.Equal(t, "1", labels[2].GetValue())
				assert.Equal(t, "service", labels[3].GetName())
				assert.Equal(t, "foo", labels[3].GetValue())
				assert.Equal(t, "subject", labels[4].GetName())
				assert.Equal(t, "CN=Test Int CA 1,O=Test,C=EU", labels[4].GetValue())

				// third certificate in the chain
				value = values[2]
				assert.LessOrEqual(t, 86400.0-value.GetGauge().GetValue(), 1.0)

				labels = value.GetLabel()
				require.Len(t, labels, 5)
				assert.Equal(t, "dns_names", labels[0].GetName())
				assert.Empty(t, labels[0].GetValue())
				assert.Equal(t, "issuer", labels[1].GetName())
				assert.Equal(t, "CN=Test Root CA 1,O=Test,C=EU", labels[1].GetValue())
				assert.Equal(t, "serial_nr", labels[2].GetName())
				assert.Equal(t, "1", labels[2].GetValue())
				assert.Equal(t, "service", labels[3].GetName())
				assert.Equal(t, "foo", labels[3].GetValue())
				assert.Equal(t, "subject", labels[4].GetName())
				assert.Equal(t, "CN=Test Root CA 1,O=Test,C=EU", labels[4].GetValue())
			},
		},
		{
			uc: "for single service for all certificates from existing key store for the first",
			collector: NewCertificateExpirationCollector(
				WithServiceKeyStore("foo", ks, WithFirstEntry()),
				WithEndEntityMonitoringOnly(false)),
			assert: func(t *testing.T, err error, result []*io_prometheus_client.MetricFamily) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, result, 1)

				metric := result[0]
				assert.Equal(t, "certificate_expiry_seconds", metric.GetName())
				assert.Equal(t, "Number of seconds until certificate expires", metric.GetHelp())
				assert.Equal(t, io_prometheus_client.MetricType_GAUGE, metric.GetType())

				values := metric.GetMetric()
				require.Len(t, values, 3)

				// first certificate in the chain
				value := values[0]
				assert.LessOrEqual(t, 3600.0-value.GetGauge().GetValue(), 1.0)

				labels := value.GetLabel()
				require.Len(t, labels, 5)
				assert.Equal(t, "dns_names", labels[0].GetName())
				assert.Empty(t, labels[0].GetValue())
				assert.Equal(t, "issuer", labels[1].GetName())
				assert.Equal(t, "CN=Test Int CA 1,O=Test,C=EU", labels[1].GetValue())
				assert.Equal(t, "serial_nr", labels[2].GetName())
				assert.Equal(t, "2", labels[2].GetValue())
				assert.Equal(t, "service", labels[3].GetName())
				assert.Equal(t, "foo", labels[3].GetValue())
				assert.Equal(t, "subject", labels[4].GetName())
				assert.Equal(t, "CN=Test EE 2,O=Test,C=EU", labels[4].GetValue())

				// second certificate in the chain
				value = values[1]
				assert.LessOrEqual(t, 43200.0-value.GetGauge().GetValue(), 1.0)

				labels = value.GetLabel()
				require.Len(t, labels, 5)
				assert.Equal(t, "dns_names", labels[0].GetName())
				assert.Empty(t, labels[0].GetValue())
				assert.Equal(t, "issuer", labels[1].GetName())
				assert.Equal(t, "CN=Test Root CA 1,O=Test,C=EU", labels[1].GetValue())
				assert.Equal(t, "serial_nr", labels[2].GetName())
				assert.Equal(t, "1", labels[2].GetValue())
				assert.Equal(t, "service", labels[3].GetName())
				assert.Equal(t, "foo", labels[3].GetValue())
				assert.Equal(t, "subject", labels[4].GetName())
				assert.Equal(t, "CN=Test Int CA 1,O=Test,C=EU", labels[4].GetValue())

				// third certificate in the chain
				value = values[2]
				assert.LessOrEqual(t, 86400.0-value.GetGauge().GetValue(), 1.0)

				labels = value.GetLabel()
				require.Len(t, labels, 5)
				assert.Equal(t, "dns_names", labels[0].GetName())
				assert.Empty(t, labels[0].GetValue())
				assert.Equal(t, "issuer", labels[1].GetName())
				assert.Equal(t, "CN=Test Root CA 1,O=Test,C=EU", labels[1].GetValue())
				assert.Equal(t, "serial_nr", labels[2].GetName())
				assert.Equal(t, "1", labels[2].GetValue())
				assert.Equal(t, "service", labels[3].GetName())
				assert.Equal(t, "foo", labels[3].GetValue())
				assert.Equal(t, "subject", labels[4].GetName())
				assert.Equal(t, "CN=Test Root CA 1,O=Test,C=EU", labels[4].GetValue())
			},
		},
		{
			uc: "for the ee certificate of a single service from existing key store entry specified by key id",
			collector: NewCertificateExpirationCollector(
				WithServiceKeyStore("foo", ks, WithKeyID("key1")),
				WithEndEntityMonitoringOnly(true)),
			assert: func(t *testing.T, err error, result []*io_prometheus_client.MetricFamily) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, result, 1)

				metric := result[0]
				assert.Equal(t, "certificate_expiry_seconds", metric.GetName())
				assert.Equal(t, "Number of seconds until certificate expires", metric.GetHelp())
				assert.Equal(t, io_prometheus_client.MetricType_GAUGE, metric.GetType())

				values := metric.GetMetric()
				require.Len(t, values, 1)

				// first certificate in the chain
				value := values[0]
				assert.LessOrEqual(t, 3600.0-value.GetGauge().GetValue(), 1.0)

				labels := value.GetLabel()
				require.Len(t, labels, 5)
				assert.Equal(t, "dns_names", labels[0].GetName())
				assert.Empty(t, labels[0].GetValue())
				assert.Equal(t, "issuer", labels[1].GetName())
				assert.Equal(t, "CN=Test Int CA 1,O=Test,C=EU", labels[1].GetValue())
				assert.Equal(t, "serial_nr", labels[2].GetName())
				assert.Equal(t, "1", labels[2].GetValue())
				assert.Equal(t, "service", labels[3].GetName())
				assert.Equal(t, "foo", labels[3].GetValue())
				assert.Equal(t, "subject", labels[4].GetName())
				assert.Equal(t, "CN=Test EE 1,O=Test,C=EU", labels[4].GetValue())
			},
		},
		{
			uc: "for ee certificates of multiple services from existing key store",
			collector: NewCertificateExpirationCollector(
				WithServiceKeyStore("foo", ks, WithKeyID("key1")),
				WithServiceKeyStore("bar", ks, WithFirstEntry()),
				WithEndEntityMonitoringOnly(true)),
			assert: func(t *testing.T, err error, result []*io_prometheus_client.MetricFamily) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, result, 1)

				metric := result[0]
				assert.Equal(t, "certificate_expiry_seconds", metric.GetName())
				assert.Equal(t, "Number of seconds until certificate expires", metric.GetHelp())
				assert.Equal(t, io_prometheus_client.MetricType_GAUGE, metric.GetType())

				values := metric.GetMetric()
				require.Len(t, values, 2)

				// service 1
				value := values[0]
				assert.LessOrEqual(t, 3600.0-value.GetGauge().GetValue(), 1.0)

				labels := value.GetLabel()
				require.Len(t, labels, 5)
				assert.Equal(t, "dns_names", labels[0].GetName())
				assert.Empty(t, labels[0].GetValue())
				assert.Equal(t, "issuer", labels[1].GetName())
				assert.Equal(t, "CN=Test Int CA 1,O=Test,C=EU", labels[1].GetValue())
				assert.Equal(t, "serial_nr", labels[2].GetName())
				assert.Equal(t, "1", labels[2].GetValue())
				assert.Equal(t, "service", labels[3].GetName())
				assert.Equal(t, "foo", labels[3].GetValue())
				assert.Equal(t, "subject", labels[4].GetName())
				assert.Equal(t, "CN=Test EE 1,O=Test,C=EU", labels[4].GetValue())

				// service 2
				value = values[1]
				assert.LessOrEqual(t, 3600.0-value.GetGauge().GetValue(), 1.0)

				labels = value.GetLabel()
				require.Len(t, labels, 5)
				assert.Equal(t, "dns_names", labels[0].GetName())
				assert.Empty(t, labels[0].GetValue())
				assert.Equal(t, "issuer", labels[1].GetName())
				assert.Equal(t, "CN=Test Int CA 1,O=Test,C=EU", labels[1].GetValue())
				assert.Equal(t, "serial_nr", labels[2].GetName())
				assert.Equal(t, "2", labels[2].GetValue())
				assert.Equal(t, "service", labels[3].GetName())
				assert.Equal(t, "bar", labels[3].GetValue())
				assert.Equal(t, "subject", labels[4].GetName())
				assert.Equal(t, "CN=Test EE 2,O=Test,C=EU", labels[4].GetValue())
			},
		},
		{
			uc: "for all certificates of multiple services from existing key store",
			collector: NewCertificateExpirationCollector(
				WithServiceKeyStore("foo", ks, WithKeyID("key1")),
				WithServiceKeyStore("bar", ks, WithFirstEntry()),
				WithEndEntityMonitoringOnly(false)),
			assert: func(t *testing.T, err error, result []*io_prometheus_client.MetricFamily) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, result, 1)

				metric := result[0]
				assert.Equal(t, "certificate_expiry_seconds", metric.GetName())
				assert.Equal(t, "Number of seconds until certificate expires", metric.GetHelp())
				assert.Equal(t, io_prometheus_client.MetricType_GAUGE, metric.GetType())

				values := metric.GetMetric()
				require.Len(t, values, 6)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			reg := prometheus.NewRegistry()
			reg.MustRegister(tc.collector)

			// WHEN
			result, err := reg.Gather()

			// THEN
			tc.assert(t, err, result)
		})
	}
}
