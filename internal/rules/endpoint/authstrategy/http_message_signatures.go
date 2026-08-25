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
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/dadrus/httpsig"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache/cachekey"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/pkix"
)

var (
	errUnsupportedAlgorithm = errors.New("unsupported algorithm")
	errUnsupportedKeySize   = errors.New("unsupported key size")
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

	informer *secrets.SecretInformer[httpsig.Signer]
	hash     atomic.Value
}

func (s *HTTPMessageSignatures) Apply(req *http.Request) error {
	logger := zerolog.Ctx(req.Context())
	logger.Debug().Msg("Applying http_message_signatures strategy to authenticate request")

	signer, ok := s.informer.Get()
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

func (s *HTTPMessageSignatures) init(appCtx app.Context) error {
	if len(s.Signer.Name) == 0 {
		s.Signer.Name = "heimdall"
	}

	if s.TTL == nil {
		s.TTL = new(time.Minute)
	}

	ref := secrets.Reference{
		Source:   s.Signer.Secret.Source,
		Selector: s.Signer.Secret.Selector,
	}

	informer, err := secrets.NewSecretInformer(
		appCtx.SecretResolver(),
		ref,
		secrets.WithConverter(s.createSigner),
		secrets.WithUpdateCallback(func(_ context.Context, secret secrets.Secret, _ httpsig.Signer) error {
			aks := secret.(secrets.AsymmetricKeySecret) //nolint:forcetypeassert

			appCtx.KeyRegistry().Notify(ref)
			s.updateHash(aks)

			return nil
		}),
	)
	if err != nil {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed resolving secret for http_message_signatures strategy",
		).CausedBy(err)
	}

	s.informer = informer

	return nil
}

func (s *HTTPMessageSignatures) createSigner(secret secrets.Secret) (httpsig.Signer, error) {
	aks, ok := secret.(secrets.AsymmetricKeySecret)
	if !ok {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"resolved secret is not suitable for signing",
		)
	}

	if err := validateSigningCertificate(aks); err != nil {
		return nil, err
	}

	key, err := toHTTPSigKey(aks)
	if err != nil {
		return nil, err
	}

	signer, err := httpsig.NewSigner(
		key,
		httpsig.WithComponents(s.Components...),
		httpsig.WithTag(s.Signer.Name),
		httpsig.WithLabel(s.Label),
		httpsig.WithTTL(*s.TTL),
	)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed creating signer",
		).CausedBy(err)
	}

	return signer, nil
}

func (s *HTTPMessageSignatures) updateHash(secret secrets.AsymmetricKeySecret) {
	key := cachekey.New("auth-strategy:http-message-signatures")

	key.WriteString(s.Label)
	key.WriteStrings(s.Components)
	key.WriteInt64(int64(*s.TTL))
	key.WriteString(s.Signer.Name)
	key.WriteString(secret.KeyID())
	key.WriteString(secret.Selector())
	key.WriteString(string(secret.Kind()))

	s.hash.Store(key.Sum())
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

	return pkix.ValidateCertificate(chain[0], opts...)
}

func toHTTPSigKey(secret secrets.AsymmetricKeySecret) (httpsig.Key, error) {
	var (
		httpSigAlg httpsig.SignatureAlgorithm
		err        error
	)

	switch key := secret.PrivateKey().(type) {
	case *rsa.PrivateKey:
		httpSigAlg, err = getRSAAlgorithm(key.Size() * 8) //nolint:mnd
	case *ecdsa.PrivateKey:
		httpSigAlg, err = getECDSAAlgorithm(key.Params().BitSize)
	case ed25519.PrivateKey:
		httpSigAlg = httpsig.Ed25519
	default:
		err = errorchain.NewWithMessagef(errUnsupportedAlgorithm, "key type: %T", key)
	}

	if err != nil {
		return httpsig.Key{}, err
	}

	return httpsig.Key{
		Algorithm: httpSigAlg,
		KeyID:     secret.KeyID(),
		Key:       secret.PrivateKey(),
	}, nil
}

func getECDSAAlgorithm(keySize int) (httpsig.SignatureAlgorithm, error) {
	switch keySize {
	case 256: //nolint:mnd
		return httpsig.EcdsaP256Sha256, nil
	case 384: //nolint:mnd
		return httpsig.EcdsaP384Sha384, nil
	case 521: //nolint:mnd
		return httpsig.EcdsaP521Sha512, nil
	default:
		return "", errorchain.NewWithMessagef(errUnsupportedKeySize, "ECDSA %d", keySize)
	}
}

func getRSAAlgorithm(keySize int) (httpsig.SignatureAlgorithm, error) {
	switch keySize {
	case 2048: //nolint:mnd
		return httpsig.RsaPssSha256, nil
	case 3072: //nolint:mnd
		return httpsig.RsaPssSha384, nil
	case 4096: //nolint:mnd
		return httpsig.RsaPssSha512, nil
	default:
		return "", errorchain.NewWithMessagef(errUnsupportedKeySize, "RSA %d", keySize)
	}
}
