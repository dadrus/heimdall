package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
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
	"github.com/dadrus/heimdall/internal/x/pkix"
)

func NewJWTSigner(conf *config.SignerConfig, logger zerolog.Logger) (heimdall.JWTSigner, error) {
	var (
		ks  keystore.KeyStore
		kse *keystore.Entry
		err error
	)

	if len(conf.KeyStore) == 0 {
		logger.Warn().
			Msg("Key store is not configured. NEVER DO IT IN PRODUCTION!!!! Generating an ECDSA P-384 key pair.")

		var privateKey *ecdsa.PrivateKey

		privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
				"failed to generate ECDSA P-384 key pair").CausedBy(err)
		}

		ks, err = keystore.NewKeyStoreFromKey(privateKey)
	} else {
		ks, err = keystore.NewKeyStoreFromPEMFile(conf.KeyStore, conf.Password)
	}

	if err != nil {
		return nil, err
	}

	logger.Info().Msg("Key store contains following entries")

	for _, entry := range ks.Entries() {
		logger.Info().
			Str("_key_id", entry.KeyID).
			Str("_algorithm", entry.Alg).
			Int("_size", entry.KeySize).
			Msg("Entry info")
	}

	if len(conf.KeyID) == 0 {
		logger.Warn().Msg("No key id for signer configured. Taking first entry from the key store")

		kse, err = ks.Entries()[0], nil
	} else {
		kse, err = ks.GetKey(conf.KeyID)
	}

	if err != nil {
		return nil, err
	}

	if len(kse.CertChain) != 0 {
		if err = pkix.ValidateCertificate(kse.CertChain[0],
			pkix.WithKeyUsage(x509.KeyUsageDigitalSignature),
			pkix.WithCurrentTime(time.Now()),
		); err != nil {
			return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"configured certificate cannot be used for JWT signing purposes").CausedBy(err)
		}
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

func (s *jwtSigner) Hash() []byte {
	hash := sha256.New()
	hash.Write([]byte(s.jwk.KeyID))
	hash.Write([]byte(s.jwk.Algorithm))
	hash.Write([]byte(s.iss))

	return hash.Sum(nil)
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
