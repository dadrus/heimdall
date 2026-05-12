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
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/secrets/cache"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

type APIKey struct {
	In     string        `mapstructure:"in"     validate:"required,oneof=cookie header query"`
	Name   string        `mapstructure:"name"   validate:"required"`
	Secret config.Secret `mapstructure:"secret" validate:"required"`

	resolver *cache.SecretResolver[string]
	hash     atomic.Value
}

func (c *APIKey) Apply(req *http.Request) error {
	logger := zerolog.Ctx(req.Context())
	logger.Debug().Msg("Applying api_key strategy to authenticate request")

	creds, ok := c.resolver.Get()
	if !ok {
		return errorchain.NewWithMessage(
			pipeline.ErrInternal,
			"api key secret is not available",
		)
	}

	switch c.In {
	case "cookie":
		req.AddCookie(&http.Cookie{Name: c.Name, Value: creds})
	case "header":
		req.Header.Set(c.Name, creds)
	case "query":
		query := req.URL.Query()
		query.Set(c.Name, creds)
		req.URL.RawQuery = query.Encode()
	default:
		return errorchain.NewWithMessagef(pipeline.ErrConfiguration,
			"unsupported in value (%s) in api key auth strategy", c.In)
	}

	return nil
}

func (c *APIKey) Hash() []byte {
	if hash, ok := c.hash.Load().([]byte); ok {
		return hash
	}

	return nil
}

func (c *APIKey) init(ctx context.Context, appCtx app.Context) error {
	c.resolver = &cache.SecretResolver[string]{
		Manager:   appCtx.SecretsManager(),
		Reference: secrets.InternalRef(c.Secret.Source, c.Secret.Selector),
		Converter: toStringSecret,
		OnUpdate: func(_ context.Context, _ secrets.Secret, value string) {
			hash := sha256.New()

			hash.Write(stringx.ToBytes(c.In))
			hash.Write(stringx.ToBytes(c.Name))
			hash.Write(stringx.ToBytes(value))

			var result [sha256.Size]byte

			c.hash.Store(hash.Sum(result[:0]))
		},
	}

	if err := c.resolver.Start(ctx); err != nil {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed resolving api key secret",
		).CausedBy(err)
	}

	return nil
}

func toStringSecret(secret secrets.Secret) (string, error) {
	ss, ok := secret.(secrets.StringSecret)
	if !ok {
		return "", secrets.ErrSecretKindMismatch
	}

	return ss.String(), nil
}
