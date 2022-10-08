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

func NewJWTSigner(ks keystore.KeyStore, conf config.SignerConfig, logger zerolog.Logger) (heimdall.JWTSigner, error) {
	var (
		kse *keystore.Entry
		err error
	)

	if len(conf.KeyID) == 0 {
		logger.Warn().Msg("No key id for signer configured. Taking first entry from the key store")

		kse, err = ks.Entries()[0], nil
	} else {
		kse, err = ks.GetKey(conf.KeyID)
	}

	if err != nil {
		return nil, err
	}

	logger.Info().Str("_key_id", kse.KeyID).Msg("Signer configured")

	return &jwtSigner{
		iss: conf.Name,
		jwk: kse.JWK(),
		key: kse.PrivateKey,
	}, nil
}

type jwtSigner struct {
	iss string
	jwk jose.JSONWebKey
	key crypto.Signer
}

func (s *jwtSigner) Hash() string {
	hash := sha256.New()
	hash.Write([]byte(s.jwk.KeyID))
	hash.Write([]byte(s.jwk.Algorithm))
	hash.Write([]byte(s.iss))

	return hex.EncodeToString(hash.Sum(nil))
}

func (s *jwtSigner) Sign(sub string, ttl time.Duration, custClaims map[string]any) (string, error) {
	signerOpts := jose.SignerOptions{}
	signerOpts.
		WithType("JWT").
		WithHeader("kid", s.jwk.KeyID).
		WithHeader("alg", s.jwk.Algorithm)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(s.jwk.Algorithm), Key: s.key},
		&signerOpts)
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
