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
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/dadrus/httpsig"
	"github.com/go-jose/go-jose/v4"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keystore"
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

type HTTPMessageSignatures struct {
	Signer     SignerConfig   `mapstructure:"signer"     validate:"required"`
	Components []string       `mapstructure:"components" validate:"gt=0,dive,required"`
	TTL        *time.Duration `mapstructure:"ttl"`
	Label      string         `mapstructure:"label"`

	mut sync.RWMutex
	// used to allow downloading the keys for signature verification purposes
	// since the http message signatures rfc does not define a format for key transport
	// JWK is used here.
	pubKeys []jose.JSONWebKey
	// used to monitor the expiration of configured certificates
	certChain []*x509.Certificate
	signer    httpsig.Signer
}

func (s *HTTPMessageSignatures) OnChanged(logger zerolog.Logger) {
	err := s.init()
	if err != nil {
		logger.Warn().Err(err).
			Str("_file", s.Signer.KeyStore.Path).
			Msg("Signer key store reload failed")
	} else {
		logger.Info().
			Str("_file", s.Signer.KeyStore.Path).
			Msg("Signer key store reloaded")
	}
}

func (s *HTTPMessageSignatures) Apply(ctx context.Context, req *http.Request) error {
	logger := zerolog.Ctx(ctx)
	logger.Debug().Msg("Applying http_message_signatures strategy to authenticate request")

	s.mut.RLock()
	defer s.mut.RUnlock()

	header, err := s.signer.Sign(httpsig.MessageFromRequest(req))
	if err != nil {
		return err
	}

	// set the updated headers
	req.Header = header

	return nil
}

func (s *HTTPMessageSignatures) Keys() []jose.JSONWebKey {
	s.mut.RLock()
	defer s.mut.RUnlock()

	return s.pubKeys
}

func (s *HTTPMessageSignatures) Hash() []byte {
	const int64BytesCount = 8

	hash := sha256.New()
	hash.Write(stringx.ToBytes(s.Label))

	for _, component := range s.Components {
		hash.Write(stringx.ToBytes(component))
	}

	if s.TTL != nil {
		ttlBytes := make([]byte, int64BytesCount)

		//nolint:gosec
		// no integer overflow during conversion possible
		binary.LittleEndian.PutUint64(ttlBytes, uint64(*s.TTL))

		hash.Write(ttlBytes)
	}

	hash.Write(stringx.ToBytes(s.Signer.Name))
	hash.Write(stringx.ToBytes(s.Signer.KeyID))

	return hash.Sum(nil)
}

func (s *HTTPMessageSignatures) Name() string { return "http message signer" }

func (s *HTTPMessageSignatures) Certificates() []*x509.Certificate {
	s.mut.RLock()
	defer s.mut.RUnlock()

	return s.certChain
}

func (s *HTTPMessageSignatures) init() error {
	ks, err := keystore.NewKeyStoreFromPEMFile(s.Signer.KeyStore.Path, s.Signer.KeyStore.Password)
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed loading keystore for http_message_signatures strategy").CausedBy(err)
	}

	var kse *keystore.Entry

	if len(s.Signer.KeyID) == 0 {
		kse, err = ks.Entries()[0], nil
	} else {
		kse, err = ks.GetKey(s.Signer.KeyID)
	}

	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed retrieving key from key store for http_message_signatures strategy").CausedBy(err)
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
				"certificate for http_message_signatures strategy cannot be used for signing purposes").
				CausedBy(err)
		}
	}

	keys := make([]jose.JSONWebKey, len(ks.Entries()))
	for idx, entry := range ks.Entries() {
		keys[idx] = entry.JWK()
	}

	signer, err := httpsig.NewSigner(
		toHTTPSigKey(kse),
		httpsig.WithComponents(s.Components...),
		httpsig.WithTag(x.IfThenElse(len(s.Signer.Name) != 0, s.Signer.Name, "heimdall")),
		httpsig.WithLabel(s.Label),
		httpsig.WithTTL(x.IfThenElseExec(s.TTL != nil,
			func() time.Duration { return *s.TTL },
			func() time.Duration { return 1 * time.Minute },
		)),
	)
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed to configure http_message_signatures strategy").CausedBy(err)
	}

	s.mut.Lock()
	defer s.mut.Unlock()

	s.signer = signer
	s.pubKeys = keys
	s.certChain = kse.CertChain

	return nil
}

func toHTTPSigKey(entry *keystore.Entry) httpsig.Key {
	var httpSigAlg httpsig.SignatureAlgorithm

	switch entry.Alg {
	case keystore.AlgRSA:
		httpSigAlg = getRSAAlgorithm(entry.KeySize)
	case keystore.AlgECDSA:
		httpSigAlg = getECDSAAlgorithm(entry.KeySize)
	default:
		panic("unsupported key algorithm: " + entry.Alg)
	}

	return httpsig.Key{
		Algorithm: httpSigAlg,
		KeyID:     entry.KeyID,
		Key:       entry.PrivateKey,
	}
}

func getECDSAAlgorithm(keySize int) httpsig.SignatureAlgorithm {
	switch keySize {
	case 256: //nolint: mnd
		return httpsig.EcdsaP256Sha256
	case 384: //nolint: mnd
		return httpsig.EcdsaP384Sha384
	case 512: //nolint: mnd
		return httpsig.EcdsaP521Sha512
	default:
		panic(fmt.Sprintf("unsupported ECDSA key size: %d", keySize))
	}
}

func getRSAAlgorithm(keySize int) httpsig.SignatureAlgorithm {
	switch keySize {
	case 2048: //nolint: mnd
		return httpsig.RsaPssSha256
	case 3072: //nolint: mnd
		return httpsig.RsaPssSha384
	case 4096: //nolint: mnd
		return httpsig.RsaPssSha512
	default:
		panic(fmt.Sprintf("unsupported RSA key size: %d", keySize))
	}
}
