package signer

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"github.com/knadh/koanf/maps"
	"github.com/rs/zerolog"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

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
	ecdsa512 = 521
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

func (s *jwtSigner) Hash() string {
	hash := sha256.New()
	hash.Write([]byte(s.kid))
	hash.Write([]byte(s.alg))
	hash.Write([]byte(s.iss))

	return hex.EncodeToString(hash.Sum(nil))
}

func (s *jwtSigner) Sign(sub string, ttl time.Duration, custClaims map[string]any) (string, error) {
	signerOpts := jose.SignerOptions{}
	signerOpts.
		WithType("JWT").
		WithHeader("kid", s.kid).
		WithHeader("alg", s.alg)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: s.alg, Key: s.key}, &signerOpts)
	if err != nil {
		return "", errorchain.NewWithMessage(heimdall.ErrInternal, "failed to create JWT signer").CausedBy(err)
	}

	claims := make(map[string]any)
	maps.Merge(custClaims, claims)

	now := time.Now().UTC()
	exp := now.Add(ttl)
	claims["exp"] = exp.Unix()
	claims["jti"] = uuid.New()
	claims["iat"] = now.Unix()
	claims["iss"] = s.iss
	claims["nbf"] = now.Unix()
	claims["sub"] = sub

	builder := jwt.Signed(signer).Claims(claims)

	rawJwt, err := builder.CompactSerialize()
	if err != nil {
		return "", errorchain.NewWithMessage(heimdall.ErrInternal, "failed to sign claims").CausedBy(err)
	}

	return rawJwt, nil
}
