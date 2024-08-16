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
	"encoding/binary"
	"fmt"
	"net/http"
	"time"

	"github.com/dadrus/httpsig"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x"
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
	Signer     SignerConfig   `mapstructure:"signer" validate:"required"`
	TTL        *time.Duration `mapstructure:"ttl"    validate:"omitempty,gt=1s"`
	Components []string       `mapstructure:"components" validate:"gt=0,dive,required"`
	Label      string         `mapstructure:"label"`
}

func (c *HTTPMessageSignatures) Apply(ctx context.Context, req *http.Request) error {
	logger := zerolog.Ctx(ctx)
	logger.Debug().Msg("Applying http_message_signatures strategy to authenticate request")

	ks, err := keystore.NewKeyStoreFromPEMFile(c.Signer.KeyStore.Path, c.Signer.KeyStore.Password)
	if err != nil {
		return err
	}

	entry, err := x.IfThenElseExecErr(len(c.Signer.KeyID) != 0,
		func() (*keystore.Entry, error) { return ks.GetKey(c.Signer.KeyID) },
		func() (*keystore.Entry, error) { return ks.Entries()[0], nil },
	)
	if err != nil {
		return err
	}

	signer, err := httpsig.NewSigner(toHTTPSigKey(entry),
		httpsig.WithComponents(c.Components...),
		httpsig.WithTag(x.IfThenElse(len(c.Signer.Name) != 0, c.Signer.Name, "heimdall")),
		httpsig.WithLabel(c.Label),
		httpsig.WithTTL(x.IfThenElseExec(c.TTL != nil,
			func() time.Duration { return *c.TTL },
			func() time.Duration { return 1 * time.Minute },
		)),
	)
	if err != nil {
		return err
	}

	header, err := signer.Sign(httpsig.MessageFromRequest(req))
	if err != nil {
		return err
	}

	// set the updated headers
	req.Header = header

	return nil
}

func (c *HTTPMessageSignatures) Hash() []byte {
	const int64BytesCount = 8

	hash := sha256.New()
	hash.Write(stringx.ToBytes(c.Label))

	for _, component := range c.Components {
		hash.Write(stringx.ToBytes(component))
	}

	if c.TTL != nil {
		ttlBytes := make([]byte, int64BytesCount)
		binary.LittleEndian.PutUint64(ttlBytes, uint64(*c.TTL))

		hash.Write(ttlBytes)
	}

	hash.Write(stringx.ToBytes(c.Signer.Name))
	hash.Write(stringx.ToBytes(c.Signer.KeyID))

	return hash.Sum(nil)
}

func toHTTPSigKey(entry *keystore.Entry) httpsig.Key {
	return httpsig.Key{
		KeyID:     entry.KeyID,
		Key:       entry.PrivateKey,
		Algorithm: toHTTPSigAlgorithm(entry),
	}
}

func toHTTPSigAlgorithm(alg *keystore.Entry) httpsig.SignatureAlgorithm {
	switch alg.Alg {
	case keystore.AlgRSA:
		return getRSAAlgorithm(alg.KeySize)
	case keystore.AlgECDSA:
		return getECDSAAlgorithm(alg.KeySize)
	default:
		panic(fmt.Sprintf("unsupported key algorithm: %s", alg.Alg))
	}
}

func getECDSAAlgorithm(keySize int) httpsig.SignatureAlgorithm {
	switch keySize {
	case 256:
		return httpsig.EcdsaP256Sha256
	case 384:
		return httpsig.EcdsaP384Sha384
	case 512:
		return httpsig.EcdsaP521Sha512
	default:
		panic(fmt.Sprintf("unsupported ECDSA key size: %d", keySize))
	}
}

func getRSAAlgorithm(keySize int) httpsig.SignatureAlgorithm {
	switch keySize {
	case 2048:
		return httpsig.RsaPssSha256
	case 3072:
		return httpsig.RsaPssSha384
	case 4096:
		return httpsig.RsaPssSha512
	default:
		panic(fmt.Sprintf("unsupported RSA key size: %d", keySize))
	}
}
