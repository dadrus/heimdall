package keystore

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"gopkg.in/square/go-jose.v2"
)

const (
	rsa2048 = 2048
	rsa3072 = 3072
	rsa4096 = 4096

	ecdsa256 = 256
	ecdsa384 = 384
	ecdsa512 = 521
)

type Entry struct {
	KeyID      string
	Alg        string
	KeySize    int
	PrivateKey crypto.Signer
	CertChain  []*x509.Certificate
}

func (e *Entry) JWK() jose.JSONWebKey {
	return jose.JSONWebKey{
		KeyID:        e.KeyID,
		Algorithm:    string(e.JOSEAlgorithm()),
		Key:          e.PrivateKey.Public(),
		Use:          "sig",
		Certificates: e.CertChain,
	}
}

func (e *Entry) JOSEAlgorithm() jose.SignatureAlgorithm {
	switch e.Alg {
	case AlgRSA:
		return getRSAAlgorithm(e.KeySize)
	case AlgECDSA:
		return getECDSAAlgorithm(e.KeySize)
	default:
		panic(fmt.Sprintf("Unsupported algorithm: %s", e.Alg))
	}
}

func getECDSAAlgorithm(keySize int) jose.SignatureAlgorithm {
	switch keySize {
	case ecdsa256:
		return jose.ES256
	case ecdsa384:
		return jose.ES384
	case ecdsa512:
		return jose.ES512
	default:
		panic(fmt.Sprintf("unsupported ECDSA key size: %d", keySize))
	}
}

func getRSAAlgorithm(keySize int) jose.SignatureAlgorithm {
	switch keySize {
	case rsa2048:
		return jose.PS256
	case rsa3072:
		return jose.PS384
	case rsa4096:
		return jose.PS512
	default:
		panic(fmt.Sprintf("unsupported RSA key size: %d", keySize))
	}
}
