// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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

package authstrategy

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/dadrus/httpsig"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	keyregistry "github.com/dadrus/heimdall/internal/keyregistry/v2"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/secrets/cache"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/pkix"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

type SignerConfig struct {
	Name   string        `mapstructure:"name"`
	Secret config.Secret `mapstructure:"secret" validate:"required"`
}

type HTTPMessageSignatures struct {
	Signer     SignerConfig   `mapstructure:"signer"     validate:"required"`
	Components []string       `mapstructure:"components" validate:"gt=0,dive,required"`
	TTL        *time.Duration `mapstructure:"ttl"`
	Label      string         `mapstructure:"label"`

	resolver *cache.SecretResolver[httpsig.Signer]
	hash     atomic.Value
}

func (s *HTTPMessageSignatures) init(ctx context.Context, appCtx app.Context) error {
	resolver := &cache.SecretResolver[httpsig.Signer]{
		Manager:   appCtx.SecretsManager(),
		Reference: secrets.InternalRef(s.Signer.Secret.Source, s.Signer.Secret.Selector),
		Converter: s.toSigner,
		OnUpdate: func(ctx context.Context, secret secrets.Secret, _ httpsig.Signer) {
			aks := secret.(secrets.AsymmetricKeySecret) //nolint:forcetypeassert

			appCtx.KeyRegistry().Notify(keyregistry.KeyInfo{Key: aks, Exportable: true})
			s.updateHash(aks)
		},
	}

	if err := resolver.Start(ctx); err != nil {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed resolving signing secret for http_message_signatures strategy",
		).CausedBy(err)
	}

	s.resolver = resolver

	return nil
}

func (s *HTTPMessageSignatures) updateHash(secret secrets.AsymmetricKeySecret) {
	const int64BytesCount = 8

	hash := sha256.New()
	hash.Write(stringx.ToBytes(s.Label))

	for _, component := range s.Components {
		hash.Write(stringx.ToBytes(component))
	}

	if s.TTL != nil {
		var ttlBytes [int64BytesCount]byte

		//nolint:gosec
		// no integer overflow during conversion possible
		binary.LittleEndian.PutUint64(ttlBytes[:], uint64(*s.TTL))

		hash.Write(ttlBytes[:])
	}

	hash.Write(stringx.ToBytes(s.Signer.Name))
	hash.Write(stringx.ToBytes(secret.Source()))
	hash.Write(stringx.ToBytes(secret.Selector()))
	hash.Write(stringx.ToBytes(string(secret.Kind())))

	s.hash.Store(hash.Sum(nil))
}

func (s *HTTPMessageSignatures) toSigner(secret secrets.Secret) (httpsig.Signer, error) {
	aks, ok := secret.(secrets.AsymmetricKeySecret)
	if !ok {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"resolved signing secret for http_message_signatures strategy is not suitable for signing",
		)
	}

	if err := validateSigningCertificate(aks); err != nil {
		return nil, err
	}

	signer, err := httpsig.NewSigner(
		toHTTPSigKey(aks),
		httpsig.WithComponents(s.Components...),
		httpsig.WithTag(x.IfThenElse(len(s.Signer.Name) != 0, s.Signer.Name, "heimdall")),
		httpsig.WithLabel(s.Label),
		httpsig.WithTTL(x.IfThenElseExec(
			s.TTL != nil,
			func() time.Duration { return *s.TTL },
			func() time.Duration { return time.Minute },
		)),
	)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed to configure http_message_signatures strategy",
		).CausedBy(err)
	}

	return signer, nil
}

func validateSigningCertificate(secret secrets.AsymmetricKeySecret) error {
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
			"certificate for http_message_signatures strategy cannot be used for signing purposes",
		).CausedBy(err)
	}

	return nil
}

func (s *HTTPMessageSignatures) Apply(ctx context.Context, req *http.Request) error {
	logger := zerolog.Ctx(ctx)
	logger.Debug().Msg("Applying http_message_signatures strategy to authenticate request")

	signer, ok := s.resolver.Get()
	if !ok {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"http_message_signatures signer is not available",
		)
	}

	header, err := signer.Sign(httpsig.MessageFromRequest(req))
	if err != nil {
		return err
	}

	req.Header = header

	return nil
}

func (s *HTTPMessageSignatures) Hash() []byte {
	if hash, ok := s.hash.Load().([]byte); ok {
		return hash
	}

	return nil
}

func toHTTPSigKey(secret secrets.AsymmetricKeySecret) httpsig.Key {
	var httpSigAlg httpsig.SignatureAlgorithm

	switch key := secret.PrivateKey().(type) {
	case *rsa.PrivateKey:
		httpSigAlg = getRSAAlgorithm(key.Size() * 8) //nolint:mnd
	case *ecdsa.PrivateKey:
		httpSigAlg = getECDSAAlgorithm(key.Params().BitSize)
	default:
		panic(fmt.Sprintf("unsupported key algorithm: %T", key))
	}

	return httpsig.Key{
		Algorithm: httpSigAlg,
		KeyID:     secret.KeyID(),
		Key:       secret.PrivateKey(),
	}
}

func getECDSAAlgorithm(keySize int) httpsig.SignatureAlgorithm {
	switch keySize {
	case 256: //nolint:mnd
		return httpsig.EcdsaP256Sha256
	case 384: //nolint:mnd
		return httpsig.EcdsaP384Sha384
	case 512: //nolint:mnd
		return httpsig.EcdsaP521Sha512
	default:
		panic(fmt.Sprintf("unsupported ECDSA key size: %d", keySize))
	}
}

func getRSAAlgorithm(keySize int) httpsig.SignatureAlgorithm {
	switch keySize {
	case 2048: //nolint:mnd
		return httpsig.RsaPssSha256
	case 3072: //nolint:mnd
		return httpsig.RsaPssSha384
	case 4096: //nolint:mnd
		return httpsig.RsaPssSha512
	default:
		panic(fmt.Sprintf("unsupported RSA key size: %d", keySize))
	}
}
