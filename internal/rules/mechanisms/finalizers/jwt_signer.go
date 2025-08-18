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

package finalizers

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/knadh/koanf/maps"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/watcher"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/pkix"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

type KeyStore struct {
	Path     string `mapstructure:"path"     validate:"required"`
	Password string `mapstructure:"password"`
}

type SignerConfig struct {
	Name     string   `mapstructure:"name"`
	KeyStore KeyStore `mapstructure:"key_store" validate:"required"`
	KeyID    string   `mapstructure:"key_id"`
}

type jwtSigner struct {
	path     string
	password string
	keyID    string
	iss      string

	mut     sync.RWMutex
	jwk     jose.JSONWebKey
	key     crypto.Signer
	pubKeys []jose.JSONWebKey
}

func newJWTSigner(conf *SignerConfig, fw watcher.Watcher) (*jwtSigner, error) {
	signer := &jwtSigner{
		path:     conf.KeyStore.Path,
		password: conf.KeyStore.Password,
		keyID:    conf.KeyID,
		iss:      x.IfThenElse(len(conf.Name) == 0, "heimdall", conf.Name),
	}

	if err := signer.load(); err != nil {
		return nil, err
	}

	if err := fw.Add(signer.path, signer); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed registering jwt signer for updates").
			CausedBy(err)
	}

	return signer, nil
}

func (s *jwtSigner) OnChanged(logger zerolog.Logger) {
	err := s.load()
	if err != nil {
		logger.Warn().Err(err).
			Str("_file", s.path).
			Msg("Signer key store reload failed")
	} else {
		logger.Info().
			Str("_file", s.path).
			Msg("Signer key store reloaded")
	}
}

func (s *jwtSigner) Hash() []byte {
	s.mut.RLock()
	jwk := s.jwk
	s.mut.RUnlock()

	hash := sha256.New()
	hash.Write(stringx.ToBytes(jwk.KeyID))
	hash.Write(stringx.ToBytes(jwk.Algorithm))
	hash.Write(stringx.ToBytes(s.iss))

	return hash.Sum(nil)
}

func (s *jwtSigner) Sign(sub string, ttl time.Duration, customClaims map[string]any) (string, error) {
	s.mut.RLock()
	jwk := s.jwk
	key := s.key
	s.mut.RUnlock()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: key},
		new(jose.SignerOptions).
			WithType("JWT").
			WithHeader("kid", jwk.KeyID).
			WithHeader("alg", jwk.Algorithm))
	if err != nil {
		return "", errorchain.NewWithMessage(heimdall.ErrInternal, "failed to create JWT signer").CausedBy(err)
	}

	claims := make(map[string]any)
	maps.Merge(customClaims, claims)

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
	s.mut.RLock()
	defer s.mut.RUnlock()

	return s.pubKeys
}

func (s *jwtSigner) activeCertificateChain() []*x509.Certificate {
	s.mut.RLock()
	defer s.mut.RUnlock()

	return s.jwk.Certificates
}

func (s *jwtSigner) load() error {
	ks, err := keystore.NewKeyStoreFromPEMFile(s.path, s.password)
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal, "failed loading keystore").
			CausedBy(err)
	}

	var kse *keystore.Entry

	if len(s.keyID) == 0 {
		kse, err = ks.Entries()[0], nil
	} else {
		kse, err = ks.GetKey(s.keyID)
	}

	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed retrieving key from key store").CausedBy(err)
	}

	if len(kse.CertChain) != 0 {
		opts := []pkix.ValidationOption{
			pkix.WithKeyUsage(x509.KeyUsageDigitalSignature),
			pkix.WithRootCACertificates([]*x509.Certificate{kse.CertChain[len(kse.CertChain)-1]}),
			pkix.WithCurrentTime(time.Now()),
		}

		if len(kse.CertChain) > 2 { //nolint: mnd
			opts = append(opts, pkix.WithIntermediateCACertificates(kse.CertChain[1:len(kse.CertChain)-1]))
		}

		if err = pkix.ValidateCertificate(kse.CertChain[0], opts...); err != nil {
			return errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"configured certificate cannot be used for JWT signing purposes").CausedBy(err)
		}
	}

	keys := make([]jose.JSONWebKey, len(ks.Entries()))
	for idx, entry := range ks.Entries() {
		keys[idx] = entry.JWK()
	}

	s.mut.Lock()
	defer s.mut.Unlock()

	s.jwk = kse.JWK()
	s.key = kse.PrivateKey
	s.pubKeys = keys

	return nil
}
