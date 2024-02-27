// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/knadh/koanf/maps"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/pkix"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

func NewJWTSigner(conf *config.Configuration, logger zerolog.Logger) (heimdall.JWTSigner, error) {
	var (
		ks  keystore.KeyStore
		kse *keystore.Entry
		err error
	)

	if len(conf.Signer.KeyStore.Path) == 0 {
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
		ks, err = keystore.NewKeyStoreFromPEMFile(conf.Signer.KeyStore.Path, conf.Signer.KeyStore.Password)
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

	if len(conf.Signer.KeyID) == 0 {
		logger.Warn().Msg("No key id for signer configured. Taking first entry from the key store")

		kse, err = ks.Entries()[0], nil
	} else {
		kse, err = ks.GetKey(conf.Signer.KeyID)
	}

	if err != nil {
		return nil, err
	}

	if len(kse.CertChain) != 0 {
		if err = pkix.ValidateCertificate(kse.CertChain[0],
			pkix.WithKeyUsage(x509.KeyUsageDigitalSignature),
			pkix.WithRootCACertificates([]*x509.Certificate{kse.CertChain[len(kse.CertChain)-1]}),
			pkix.WithCurrentTime(time.Now()),
		); err != nil {
			logger.Error().Err(err).Msg("Failed validating certificate")

			return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"configured certificate cannot be used for JWT signing purposes").CausedBy(err)
		}
	}

	logger.Info().Str("_key_id", kse.KeyID).Msg("Signer configured")

	return &jwtSigner{
		iss: conf.Signer.Name,
		jwk: kse.JWK(),
		key: kse.PrivateKey,
		ks:  ks,
	}, nil
}

type jwtSigner struct {
	iss string
	jwk jose.JSONWebKey
	key crypto.Signer
	ks  keystore.KeyStore
}

func (s *jwtSigner) Hash() []byte {
	hash := sha256.New()
	hash.Write(stringx.ToBytes(s.jwk.KeyID))
	hash.Write(stringx.ToBytes(s.jwk.Algorithm))
	hash.Write(stringx.ToBytes(s.iss))

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

	rawJwt, err := builder.Serialize()
	if err != nil {
		return "", errorchain.NewWithMessage(heimdall.ErrInternal, "failed to sign claims").CausedBy(err)
	}

	return rawJwt, nil
}

func (s *jwtSigner) Keys() []jose.JSONWebKey {
	keys := make([]jose.JSONWebKey, len(s.ks.Entries()))

	for idx, entry := range s.ks.Entries() {
		keys[idx] = entry.JWK()
	}

	return keys
}
