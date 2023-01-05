package certmon

import (
	"crypto/x509"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type certificateExpirationCollector struct {
	service string
	cert    *x509.Certificate
	expiry  *prometheus.GaugeVec
}

func (c *certificateExpirationCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.expiry.WithLabelValues("service", "issuer", "serial_nr", "subject", "dns_names").Desc()
}

func (c *certificateExpirationCollector) Collect(ch chan<- prometheus.Metric) {
	labels := prometheus.Labels{
		"service":   c.service,
		"issuer":    c.cert.Issuer.String(),
		"serial_nr": c.cert.SerialNumber.String(),
		"subject":   c.cert.Subject.String(),
		"dns_names": strings.Join(c.cert.DNSNames, ","),
	}

	since := time.Until(c.cert.NotAfter)
	c.expiry.With(labels).Set(since.Seconds())
	ch <- c.expiry.With(labels)
}

func NewCertificateExpirationCollector(service string, cert *x509.Certificate) prometheus.Collector {
	return &certificateExpirationCollector{
		service: service,
		cert:    cert,
		expiry: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "certificate",
			Subsystem: "expiry",
			Name:      "seconds",
			Help:      "Number of seconds until certificate expires",
		},
			[]string{"service", "issuer", "serial_nr", "subject", "dns_names"}),
	}
}
