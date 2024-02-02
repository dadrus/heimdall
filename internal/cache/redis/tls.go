package redis

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"os"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/keystore"
)

func configureTLS(tlsCfg *config.TLS, additionalCa string) (*tls.Config, error) {
	var (
		ks  keystore.KeyStore
		kse *keystore.Entry
		err error
	)

	// Expects the client certificate and PK in a PEM keystore.
	ks, err = keystore.NewKeyStoreFromPEMFile(tlsCfg.KeyStore.Path, tlsCfg.KeyStore.Password)

	if err != nil {
		return nil, err
	}

	// cross check the PK with the one configured.
	if len(tlsCfg.KeyID) != 0 {
		if kse, err = ks.GetKey(tlsCfg.KeyID); err != nil {
			return nil, err
		}
	} else {
		kse = ks.Entries()[0]
	}

	cert, err := keystore.ToTLSCertificate(kse)
	if err != nil {
		return nil, err
	}

	// possibly add special CA Certificates not contained in the standard locations.
	caCert, err := os.ReadFile(additionalCa)
	if err != nil {
		log.Fatal(err)

		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// disable "G402 (CWE-295): TLS MinVersion too low. (Confidence: HIGH, Severity: HIGH)" -> False positive.
	// #nosec G402
	tls := &tls.Config{
		MinVersion:   tlsCfg.MinVersion.OrDefault(),
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	return tls, nil
}
