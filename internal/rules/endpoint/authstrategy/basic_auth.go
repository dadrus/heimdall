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

package authstrategy

import (
	"context"
	"crypto/sha256"
	"net/http"
	"sync/atomic"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

type basicAuthCredentials struct {
	UserID   string `json:"user_id"  validate:"required"`
	Password string `json:"password" validate:"required"`
}

func (c basicAuthCredentials) Hash() []byte {
	hash := sha256.New()

	hash.Write(stringx.ToBytes(c.UserID))
	hash.Write(stringx.ToBytes(c.Password))

	var result [sha256.Size]byte

	return hash.Sum(result[:0])
}

type BasicAuth struct {
	Credentials config.Secret `mapstructure:"credentials" validate:"required"`

	informer *secrets.CredentialsInformer[basicAuthCredentials]
	hash     atomic.Value
}

func (c *BasicAuth) Apply(req *http.Request) error {
	logger := zerolog.Ctx(req.Context())
	logger.Debug().Msg("Applying basic_auth strategy to authenticate request")

	creds, ok := c.informer.Get(req.Context())
	if !ok {
		return errorchain.NewWithMessage(
			pipeline.ErrInternal,
			"basic auth credentials are not available",
		)
	}

	req.SetBasicAuth(creds.UserID, creds.Password)

	return nil
}

func (c *BasicAuth) Hash() []byte {
	if hash, ok := c.hash.Load().([]byte); ok {
		return hash
	}

	return nil
}

func (c *BasicAuth) init(ctx context.Context, appCtx app.Context) error {
	informer, err := secrets.NewCredentialsInformer(
		ctx,
		appCtx.SecretResolver(),
		secrets.Reference{Source: c.Credentials.Source, Selector: c.Credentials.Selector},
		secrets.CredentialsInformerOptions[basicAuthCredentials]{
			Converter: toBasicAuthCredentials(appCtx.DecoderFactory()),
			OnUpdate: func(_ context.Context, _ secrets.Credentials, creds basicAuthCredentials) error {
				c.hash.Store(creds.Hash())

				return nil
			},
		},
	)
	if err != nil {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed resolving basic auth credentials",
		).CausedBy(err)
	}

	c.informer = informer

	return nil
}

func toBasicAuthCredentials(df encoding.DecoderFactory) func(creds secrets.Credentials) (basicAuthCredentials, error) {
	return func(creds secrets.Credentials) (basicAuthCredentials, error) {
		var data basicAuthCredentials

		dec := df.Decoder()

		if err := dec.DecodeMap(&data, creds.Values()); err != nil {
			return basicAuthCredentials{}, errorchain.NewWithMessage(
				pipeline.ErrConfiguration,
				"failed decoding basic auth credentials",
			).CausedBy(err)
		}

		return data, nil
	}
}
