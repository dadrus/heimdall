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
	"net/http"
	"sync/atomic"
	"time"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	cc "github.com/dadrus/heimdall/internal/rules/oauth2/clientcredentials"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/secrets/cache"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/rs/zerolog"
)

type HeaderConfig struct {
	Name   string `mapstructure:"name"   validate:"required"`
	Scheme string `mapstructure:"scheme"`
}

type OAuth2ClientCredentials struct {
	TokenURL    string         `mapstructure:"token_url"   validate:"required,url,enforced=istls"`
	Credentials config.Secret  `mapstructure:"credentials" validate:"required"`
	AuthMethod  cc.AuthMethod  `mapstructure:"auth_method" validate:"omitempty,oneof=basic_auth request_body"`
	Scopes      []string       `mapstructure:"scopes"`
	TTL         *time.Duration `mapstructure:"cache_ttl"`
	Header      *HeaderConfig  `mapstructure:"header"`

	resolver *cache.CredentialsResolver[cc.Config]
	hash     atomic.Value
}

func (c *OAuth2ClientCredentials) init(ctx context.Context, appCtx app.Context) error {
	if c.Header == nil {
		c.Header = &HeaderConfig{Name: "Authorization", Scheme: "Bearer"}
	}

	resolver := &cache.CredentialsResolver[cc.Config]{
		Manager:   appCtx.SecretsManager(),
		Reference: secrets.InternalRef(c.Credentials.Source, c.Credentials.Selector),
		Converter: c.toClientCredentialsConfig,
		OnUpdate: func(_ context.Context, _ secrets.Credentials, cfg cc.Config) {
			c.hash.Store(cfg.Hash())
		},
	}

	if err := resolver.Start(ctx); err != nil {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed resolving oauth2 client credentials",
		).CausedBy(err)
	}

	c.resolver = resolver

	return nil
}

func (c *OAuth2ClientCredentials) Apply(ctx context.Context, req *http.Request) error {
	logger := zerolog.Ctx(ctx)
	logger.Debug().Msg("Applying oauth2_client_credentials strategy to authenticate request")

	cfg, ok := c.resolver.Get()
	if !ok {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"oauth2 client credentials are not available",
		)
	}

	token, err := cfg.Token(ctx)
	if err != nil {
		return err
	}

	req.Header.Set(c.Header.Name, c.Header.Scheme+" "+token.AccessToken)

	return nil
}

func (c *OAuth2ClientCredentials) Hash() []byte {
	if hash, ok := c.hash.Load().([]byte); ok {
		return hash
	}

	return nil
}

func (c *OAuth2ClientCredentials) toClientCredentialsConfig(creds secrets.Credentials) (cc.Config, error) {
	type credentials struct {
		ClientID     string `mapstructure:"client_id"     validate:"required"`
		ClientSecret string `mapstructure:"client_secret" validate:"required"`
	}

	var data credentials

	if err := creds.Decode(&data); err != nil {
		return cc.Config{}, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed decoding oauth2 client credentials",
		).CausedBy(err)
	}

	return cc.Config{
		TokenURL:     c.TokenURL,
		ClientID:     data.ClientID,
		ClientSecret: data.ClientSecret,
		AuthMethod:   c.AuthMethod,
		Scopes:       c.Scopes,
		TTL:          c.TTL,
	}, nil
}
