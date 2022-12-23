package keystore

import (
	"crypto/tls"
	"errors"
)

var ErrNoCertificatePresent = errors.New("no certificate present")

func ToTLSCertificate(entry *Entry) (tls.Certificate, error) {
	if len(entry.CertChain) == 0 {
		return tls.Certificate{}, ErrNoCertificatePresent
	}

	cert := tls.Certificate{
		PrivateKey: entry.PrivateKey,
		Leaf:       entry.CertChain[0],
	}

	for _, cer := range entry.CertChain {
		cert.Certificate = append(cert.Certificate, cer.Raw)
	}

	return cert, nil
}
