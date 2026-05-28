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
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/knadh/koanf/maps"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/keymaterial/joseadapter"
	"github.com/dadrus/heimdall/internal/keyregistry"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/pkix"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

type SignerConfig struct {
	Name   string        `mapstructure:"name"`
	Secret config.Secret `mapstructure:"secret" validate:"required"`
}

type jwtSigner struct {
	iss      string
	ko       keyregistry.KeyObserver
	ref      secrets.Reference
	informer *secrets.SecretInformer[jose.Signer]
	hash     atomic.Value
}

func newJWTSigner(
	conf *SignerConfig,
	sm secrets.Resolver,
	ko keyregistry.KeyObserver,
) (*jwtSigner, error) {
	signer := &jwtSigner{
		iss: x.IfThenElse(len(conf.Name) == 0, "heimdall", conf.Name),
		ko:  ko,
		ref: secrets.Reference{Source: conf.Secret.Source, Selector: conf.Secret.Selector},
	}

	var err error

	signer.informer, err = secrets.NewSecretInformer(
		sm,
		signer.ref,
		secrets.WithConverter(createJOSESigner),
		secrets.WithUpdateCallback(signer.onSecretUpdated),
	)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed creating secret informer for jwt signing material",
		).CausedBy(err)
	}

	return signer, nil
}

func (s *jwtSigner) Hash() []byte {
	if hash, ok := s.hash.Load().([]byte); ok {
		return hash
	}

	return nil
}

func (s *jwtSigner) Sign(sub string, ttl time.Duration, customClaims map[string]any) (string, error) {
	signer, ok := s.informer.Get()
	if !ok {
		return "", errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"jwt signing material is not available",
		)
	}

	claims := make(map[string]any, len(customClaims)+6)
	maps.Merge(customClaims, claims)

	now := time.Now().UTC()
	claims["exp"] = now.Add(ttl).Unix()
	claims["jti"] = uuid.New()
	claims["iat"] = now.Unix()
	claims["iss"] = s.iss
	claims["nbf"] = now.Unix()
	claims["sub"] = sub

	rawJwt, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", errorchain.NewWithMessage(
			pipeline.ErrInternal,
			"failed to sign claims",
		).CausedBy(err)
	}

	return rawJwt, nil
}

func (s *jwtSigner) updateHash(secret secrets.AsymmetricKeySecret) {
	const int64BytesCount = 8

	var ttlBytes [int64BytesCount]byte

	now := time.Now().UTC().Unix()

	//nolint:gosec
	// no integer overflow during conversion possible
	binary.LittleEndian.PutUint64(ttlBytes[:], uint64(now))

	hash := sha256.New()
	hash.Write(stringx.ToBytes(s.iss))
	hash.Write(ttlBytes[:])
	hash.Write(stringx.ToBytes(secret.Selector()))
	hash.Write(stringx.ToBytes(string(secret.Kind())))
	hash.Write(stringx.ToBytes(secret.KeyID()))

	s.hash.Store(hash.Sum(nil))
}

func (s *jwtSigner) onSecretUpdated(_ context.Context, secret secrets.Secret, _ jose.Signer) error {
	aks := secret.(secrets.AsymmetricKeySecret) //nolint:forcetypeassert

	s.updateHash(aks)
	s.ko.Notify(s.ref)

	return nil
}

func createJOSESigner(secret secrets.Secret) (jose.Signer, error) {
	aks, ok := secret.(secrets.AsymmetricKeySecret)
	if !ok {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"secret is not suitable for signing",
		)
	}

	if err := validateJWTSigningCertificate(aks); err != nil {
		return nil, err
	}

	jwk, err := joseadapter.ToJWK(aks)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed creating jwk from secret",
		).CausedBy(err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
			Key:       aks.PrivateKey(),
		},
		new(jose.SignerOptions).
			WithType("JWT").
			WithHeader("kid", jwk.KeyID).
			WithHeader("alg", jwk.Algorithm),
	)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrInternal,
			"failed to create JOSE signer",
		).CausedBy(err)
	}

	return signer, nil
}

func validateJWTSigningCertificate(secret secrets.AsymmetricKeySecret) error {
	chain := secret.CertChain()
	if len(chain) == 0 {
		return nil
	}

	opts := []pkix.ValidationOption{
		pkix.WithKeyUsage(x509.KeyUsageDigitalSignature), //nolint:gosec
		pkix.WithRootCACertificates([]*x509.Certificate{chain[len(chain)-1]}),
		pkix.WithCurrentTime(time.Now()),
	}

	if len(chain) > 2 { //nolint:mnd
		opts = append(opts, pkix.WithIntermediateCACertificates(chain[1:len(chain)-1]))
	}

	if err := pkix.ValidateCertificate(chain[0], opts...); err != nil {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"configured certificate cannot be used for JWT signing purposes",
		).CausedBy(err)
	}

	return nil
}
