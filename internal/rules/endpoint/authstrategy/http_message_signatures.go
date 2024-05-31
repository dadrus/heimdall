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
	"net/http"
	"time"

	"github.com/offblocks/httpsig"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

type SignatureConfig struct {
	TTL   *time.Duration `mapstructure:"ttl"`
	KeyID string         `mapstructure:"key_id" validate:"required"`
}

type HTTPMessageSignatures struct {
	Components []string        `mapstructure:"components" validate:"gt=0,dive,required"`
	Signature  SignatureConfig `mapstructure:"signature"  validate:"required"`
}

func (c *HTTPMessageSignatures) Apply(ctx context.Context, req *http.Request) error {
	logger := zerolog.Ctx(ctx)
	logger.Debug().Msg("Applying http_message_signatures strategy to authenticate request")

	// TODO: there is a need to have access to the Signer impl here

	now := time.Now()
	// TODO: tag is the same as iss for jwt and corresponds to signer.name in heimdall's configuration
	tag := "foo"

	var expires time.Time

	if c.Signature.TTL != nil {
		expires = now.Add(*c.Signature.TTL)
	}

	signer := httpsig.NewSigner(
		httpsig.WithSignParams(
			httpsig.ParamKeyID,
			httpsig.ParamAlg,
			httpsig.ParamCreated,
			httpsig.ParamExpires,
			httpsig.ParamNonce,
			httpsig.ParamTag,
		),
		httpsig.WithSignParamValues(&httpsig.SignatureParameters{
			Created: &now,
			Expires: &expires,
			Tag:     &tag,
		}),
		httpsig.WithSignFields(c.Components...),
		// TODO: the below should be resolved via signer (see other todos above)
		//httpsig.WithSignEcdsaP256Sha256("key1", privKey),
	)

	header, err := signer.Sign(httpsig.MessageFromRequest(req))
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal, "failed to sign request").CausedBy(err)
	}

	// set the updated headers
	req.Header = header

	return nil
}

func (c *HTTPMessageSignatures) Hash() []byte {
	const int64BytesCount = 8

	hash := sha256.New()

	for _, component := range c.Components {
		hash.Write(stringx.ToBytes(component))
	}

	if c.Signature.TTL != nil {
		ttlBytes := make([]byte, int64BytesCount)
		binary.LittleEndian.PutUint64(ttlBytes, uint64(*c.Signature.TTL))

		hash.Write(ttlBytes)
	}

	hash.Write(stringx.ToBytes(c.Signature.KeyID))

	return hash.Sum(nil)
}
