package signer

import (
	"crypto"

	"github.com/rs/zerolog"
	"gopkg.in/square/go-jose.v2"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

const (
	rsa2048 = 2048
	rsa3072 = 3072
	rsa4096 = 4096

	ecdsa256 = 256
	ecdsa384 = 384
	ecdsa512 = 512
)

func newJWTSigner(ks keystore.KeyStore, conf config.Configuration, logger zerolog.Logger) (heimdall.JWTSigner, error) {
	var (
		kse *keystore.Entry
		err error
	)

	if len(conf.Signer.KeyID) == 0 {
		logger.Warn().Msg("No key id for signer configured. Taking first entry from the key store")

		kse, err = ks.Entries()[0], nil
	} else {
		kse, err = ks.GetKey(conf.Signer.KeyID)
	}

	if err != nil {
		return nil, err
	}

	alg, err := getJOSEAlgorithm(kse)
	if err != nil {
		return nil, err
	}

	return &jwtSigner{
		iss: conf.Signer.Name,
		kid: kse.KeyID,
		alg: alg,
		key: kse.PrivateKey,
	}, nil
}

func getJOSEAlgorithm(key *keystore.Entry) (jose.SignatureAlgorithm, error) {
	switch key.Alg {
	case keystore.AlgRSA:
		return getRSAAlgorithm(key)
	case keystore.AlgECDSA:
		return getECDSAAlgorithm(key)
	default:
		return "", errorchain.
			NewWithMessage(heimdall.ErrInternal, "unsupported signature key type")
	}
}

func getECDSAAlgorithm(key *keystore.Entry) (jose.SignatureAlgorithm, error) {
	switch key.KeySize {
	case ecdsa256:
		return jose.ES256, nil
	case ecdsa384:
		return jose.ES384, nil
	case ecdsa512:
		return jose.ES512, nil
	default:
		return "", errorchain.
			NewWithMessage(heimdall.ErrInternal, "unsupported ECDSA key size")
	}
}

func getRSAAlgorithm(key *keystore.Entry) (jose.SignatureAlgorithm, error) {
	switch key.KeySize {
	case rsa2048:
		return jose.PS256, nil
	case rsa3072:
		return jose.PS384, nil
	case rsa4096:
		return jose.PS512, nil
	default:
		return "", errorchain.
			NewWithMessage(heimdall.ErrInternal, "unsupported RSA key size")
	}
}

type jwtSigner struct {
	iss string
	kid string
	alg jose.SignatureAlgorithm
	key crypto.Signer
}

func (s *jwtSigner) Name() string                       { return s.iss }
func (s *jwtSigner) KeyID() string                      { return s.kid }
func (s *jwtSigner) Algorithm() jose.SignatureAlgorithm { return s.alg }
func (s *jwtSigner) Key() crypto.Signer                 { return s.key }
