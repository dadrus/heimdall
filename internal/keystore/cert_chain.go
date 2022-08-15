package keystore

import (
	"bytes"
	"crypto"
	"crypto/x509"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func FindChain(key crypto.PublicKey, pool []*x509.Certificate) []*x509.Certificate {
	pubKey, ok := key.(interface {
		Equal(x crypto.PublicKey) bool
	})
	if !ok {
		return nil
	}

	for _, cert := range pool {
		if pubKey.Equal(cert.PublicKey) {
			return buildChain([]*x509.Certificate{cert}, pool)
		}
	}

	return nil
}

func buildChain(chain []*x509.Certificate, issuerCandidates []*x509.Certificate) []*x509.Certificate {
	child := chain[len(chain)-1]

	for _, candidate := range issuerCandidates {
		if child.Equal(candidate) {
			continue
		} else if isIssuerOf(child, candidate) {
			return buildChain(append(chain, candidate), issuerCandidates)
		}
	}

	return chain
}

func isIssuerOf(child, potentialIssuer *x509.Certificate) bool {
	if len(child.AuthorityKeyId) != 0 && len(potentialIssuer.SubjectKeyId) != 0 {
		return bytes.Equal(child.AuthorityKeyId, potentialIssuer.SubjectKeyId)
	}

	return bytes.Equal(child.RawIssuer, potentialIssuer.RawSubject)
}

func ValidateChain(chain []*x509.Certificate) error {
	// the validation of the chain happens without the usage of the system
	// trust store. Given the way how the buildChain function works, the last
	// certificate in the chain is considered to be the root of trust, the first
	// is the actual end entity certificate and all others are intermediaries.
	// That also means, that if the chain consists of just one certificate, it is
	// trusted explicitly.
	const certificateCount = 2

	rootPool := x509.NewCertPool()
	intermediatePool := x509.NewCertPool()

	rootPool.AddCert(chain[len(chain)-1])

	if len(chain) > certificateCount {
		for i := 1; i < len(chain)-1; i++ {
			intermediatePool.AddCert(chain[i])
		}
	}

	if _, err := chain[0].Verify(
		x509.VerifyOptions{
			Roots:         rootPool,
			Intermediates: intermediatePool,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		},
	); err != nil {
		return errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to verify %s certificate", chain[0].Subject.String()).CausedBy(err)
	}

	if chain[0].KeyUsage&x509.KeyUsageDigitalSignature != x509.KeyUsageDigitalSignature {
		return errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"certificate %s cannot be used for digital signature purposes", chain[0].Subject.String())
	}

	return nil
}
