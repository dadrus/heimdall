package pem

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

type PEMBlockOption func(*pem.Block)

func WithPEMHeader(key, value string) PEMBlockOption {
	return func(block *pem.Block) {
		block.Headers[key] = value
	}
}

func WithX509Certificate(cert *x509.Certificate, opts ...PEMBlockOption) PEMEntryOption {
	return func(block *pem.Block) error {
		block.Type = "CERTIFICATE"
		block.Bytes = cert.Raw

		for _, opt := range opts {
			opt(block)
		}

		return nil
	}
}

func WithECDSAPublicKey(key *ecdsa.PublicKey, opts ...PEMBlockOption) PEMEntryOption {
	return func(block *pem.Block) error {
		raw, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return err
		}

		block.Type = "ECDSA PUBLIC KEY"
		block.Bytes = raw

		for _, opt := range opts {
			opt(block)
		}

		return nil
	}
}

func WithECDSAPrivateKey(key *ecdsa.PrivateKey, opts ...PEMBlockOption) PEMEntryOption {
	return func(block *pem.Block) error {
		raw, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}

		block.Type = "EC PRIVATE KEY"
		block.Bytes = raw

		for _, opt := range opts {
			opt(block)
		}

		return nil
	}
}

func WithRSAPrivateKey(key *rsa.PrivateKey, opts ...PEMBlockOption) PEMEntryOption {
	return func(block *pem.Block) error {
		block.Type = "RSA PRIVATE KEY"
		block.Bytes = x509.MarshalPKCS1PrivateKey(key)

		for _, opt := range opts {
			opt(block)
		}

		return nil
	}
}

type PEMEntryOption func(*pem.Block) error

func BuildPEM(opts ...PEMEntryOption) ([]byte, error) {
	buf := new(bytes.Buffer)

	for _, opt := range opts {
		block := &pem.Block{Headers: make(map[string]string)}

		err := opt(block)
		if err != nil {
			return nil, err
		}

		if err = pem.Encode(buf, block); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}
