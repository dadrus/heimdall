package truststore

import (
	"crypto/x509"
	"os"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
)

const pemBlockTypeCertificate = "CERTIFICATE"

type TrustStore []*x509.Certificate

func (ts *TrustStore) addEntry(idx int, blockType string, _ map[string]string, content []byte) error {
	var (
		cert *x509.Certificate
		err  error
	)

	switch blockType {
	case pemBlockTypeCertificate:
		cert, err = x509.ParseCertificate(content)
	default:
		return errorchain.NewWithMessagef(heimdall.ErrInternal,
			"unsupported entry '%s' entry in the pem file", blockType)
	}

	if err != nil {
		return errorchain.NewWithMessagef(heimdall.ErrInternal,
			"failed to parse %d entry in the pem file", idx).CausedBy(err)
	}

	*ts = append(*ts, cert)

	return nil
}

func NewTrustStoreFromPEMFile(pemFilePath string) (TrustStore, error) {
	fInfo, err := os.Stat(pemFilePath)
	if err != nil {
		return nil, err
	}

	if fInfo.IsDir() {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration, "'%s' is not a file", pemFilePath)
	}

	contents, err := os.ReadFile(pemFilePath)
	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to read %s", pemFilePath).CausedBy(err)
	}

	return NewTrustStoreFromPEMBytes(contents)
}

func NewTrustStoreFromPEMBytes(pemBytes []byte) (TrustStore, error) {
	var certs TrustStore

	err := pemx.ReadPEM(pemBytes, certs.addEntry)

	return certs, err
}
