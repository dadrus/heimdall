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
	"github.com/dadrus/heimdall/internal/secrets/informer"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

type basicAuthCredentials struct {
	UserID   string `mapstructure:"user_id"  validate:"required"`
	Password string `mapstructure:"password" validate:"required"`
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

	resolver *informer.CredentialsInformer[basicAuthCredentials]
	hash     atomic.Value
}

func (c *BasicAuth) Apply(req *http.Request) error {
	logger := zerolog.Ctx(req.Context())
	logger.Debug().Msg("Applying basic_auth strategy to authenticate request")

	creds, ok := c.resolver.Get()
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
	c.resolver = &informer.CredentialsInformer[basicAuthCredentials]{
		Manager:   appCtx.SecretsManager(),
		Reference: secrets.InternalRef(c.Credentials.Source, c.Credentials.Selector),
		Converter: toBasicAuthCredentials,
		OnUpdate: func(_ context.Context, _ secrets.Credentials, creds basicAuthCredentials) {
			c.hash.Store(creds.Hash())
		},
	}

	if err := c.resolver.Start(ctx); err != nil {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed resolving basic auth credentials",
		).CausedBy(err)
	}

	return nil
}

func toBasicAuthCredentials(creds secrets.Credentials) (basicAuthCredentials, error) {
	var data basicAuthCredentials

	err := creds.Decode(&data)

	return data, err
}
