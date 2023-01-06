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
