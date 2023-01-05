package prometheus

import (
	"crypto/x509"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dadrus/heimdall/internal/keystore"
)

type service struct {
	name         string
	certificates []*x509.Certificate
}

type certificateExpirationCollector struct {
	services           []*service
	monitorEECertsOnly bool
	expiry             *prometheus.GaugeVec
}

type Option func(*certificateExpirationCollector)

type CertificateGetter func(ks keystore.KeyStore) []*x509.Certificate

func WithKeyID(keyID string) CertificateGetter {
	return func(ks keystore.KeyStore) []*x509.Certificate {
		entry, err := ks.GetKey(keyID)
		if err != nil {
			return nil
		}

		return entry.CertChain
	}
}

func WithFirstEntry() CertificateGetter {
	return func(ks keystore.KeyStore) []*x509.Certificate {
		entries := ks.Entries()
		if len(entries) == 0 {
			return nil
		}

		return entries[0].CertChain
	}
}

func WithServiceCertificates(serviceName string, certs []*x509.Certificate) Option {
	return func(collector *certificateExpirationCollector) {
		if len(certs) != 0 {
			collector.services = append(collector.services, &service{
				name:         serviceName,
				certificates: certs,
			})
		}
	}
}

func WithServiceKeyStore(serviceName string, ks keystore.KeyStore, certGetter CertificateGetter) Option {
	if ks != nil {
		return WithServiceCertificates(serviceName, certGetter(ks))
	}

	return func(collector *certificateExpirationCollector) {}
}

func WithEndEntityMonitoringOnly(flag bool) Option {
	return func(collector *certificateExpirationCollector) {
		collector.monitorEECertsOnly = flag
	}
}

func (c *certificateExpirationCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.expiry.WithLabelValues("service", "issuer", "serial_nr", "subject", "dns_names").Desc()
}

func (c *certificateExpirationCollector) Collect(ch chan<- prometheus.Metric) {
	for _, srv := range c.services {
		if c.monitorEECertsOnly {
			cert := srv.certificates[0]

			labels := prometheus.Labels{
				"service":   srv.name,
				"issuer":    cert.Issuer.String(),
				"serial_nr": cert.SerialNumber.String(),
				"subject":   cert.Subject.String(),
				"dns_names": strings.Join(cert.DNSNames, ","),
			}

			since := time.Until(cert.NotAfter)
			c.expiry.With(labels).Set(since.Seconds())
			ch <- c.expiry.With(labels)
		} else {
			for _, cert := range srv.certificates {
				labels := prometheus.Labels{
					"service":   srv.name,
					"issuer":    cert.Issuer.String(),
					"serial_nr": cert.SerialNumber.String(),
					"subject":   cert.Subject.String(),
					"dns_names": strings.Join(cert.DNSNames, ","),
				}

				since := time.Until(cert.NotAfter)
				c.expiry.With(labels).Set(since.Seconds())
				ch <- c.expiry.With(labels)
			}
		}
	}
}

func NewCertificateExpirationCollector(opts ...Option) prometheus.Collector {
	collector := &certificateExpirationCollector{
		expiry: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "certificate",
			Subsystem: "expiry",
			Name:      "seconds",
			Help:      "Number of seconds until certificate expires",
		},
			[]string{"service", "issuer", "serial_nr", "subject", "dns_names"}),
	}

	for _, opt := range opts {
		opt(collector)
	}

	return collector
}
