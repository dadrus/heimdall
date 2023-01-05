package prometheus

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCertificateExpirationCollector(t *testing.T) {
	// GIVEN
	rootCA1, err := testsupport.NewRootCA("Test Root CA 1", time.Hour*1)
	require.NoError(t, err)

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCertificateExpirationCollector("foo", rootCA1.Certificate))

	// WHEN
	result, err := reg.Gather()

	// THEN
	require.NoError(t, err)
	require.Len(t, result, 1)

	metric := result[0]
	assert.Equal(t, "certificate_expiry_seconds", metric.GetName())
	assert.Equal(t, "Number of seconds until certificate expires", metric.GetHelp())
	assert.Equal(t, io_prometheus_client.MetricType_GAUGE, metric.GetType())

	values := metric.GetMetric()
	require.Len(t, values, 1)
	assert.LessOrEqual(t, values[0].GetGauge().GetValue(), 3600.0)

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
}
