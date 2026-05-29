package pem

import (
	"context"
	"crypto/x509"

	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type certStore []*x509.Certificate

func (s certStore) getSecret(_ context.Context, _ provider.Selector) (provider.Secret, error) {
	return nil, provider.ErrUnsupportedOperation
}

func (s certStore) getSecretSet(_ context.Context, _ provider.Selector) ([]provider.Secret, error) {
	return nil, provider.ErrUnsupportedOperation
}

func (s certStore) getCertificateBundle(_ context.Context, _ provider.Selector) (provider.CertificateBundle, error) {
	return provider.NewCertificateBundle("", s), nil
}

func (s certStore) sameKind(other store) bool {
	_, ok := other.(certStore)

	return ok
}

func newCertificateStoreFromPEMBytes(contents []byte) (certStore, error) {
	blocks := readPEMBlocks(contents)
	certs := make([]*x509.Certificate, 0, len(blocks))

	for idx, block := range blocks {
		if block.Type != pemBlockTypeCertificate {
			return nil, errorchain.NewWithMessagef(provider.ErrInternal,
				"unsupported entry '%s' in the pem file", block.Type)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errorchain.NewWithMessagef(provider.ErrInternal,
				"failed to parse %d entry in the pem file", idx).CausedBy(err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errorchain.NewWithMessage(provider.ErrConfiguration,
			"no certificate material present in the certificate store")
	}

	return certs, nil
}
