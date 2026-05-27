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

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/oauth2/clientcredentials"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type headerConfig struct {
	Name   string `mapstructure:"name"   validate:"required"`
	Scheme string `mapstructure:"scheme"`
}

type OAuth2ClientCredentials struct {
	TokenURL    string                       `mapstructure:"token_url"   validate:"required,url,enforced=istls"`
	Credentials config.Secret                `mapstructure:"credentials" validate:"required"`
	AuthMethod  clientcredentials.AuthMethod `mapstructure:"auth_method" validate:"omitempty,oneof=basic_auth request_body"` //nolint:lll
	Scopes      []string                     `mapstructure:"scopes"`
	TTL         *time.Duration               `mapstructure:"cache_ttl"`
	Header      *headerConfig                `mapstructure:"header"`

	appCtx   app.Context
	informer *secrets.CredentialsInformer[clientcredentials.Config]
	hash     atomic.Value
}

func (c *OAuth2ClientCredentials) Apply(req *http.Request) error {
	ctx := req.Context()
	logger := zerolog.Ctx(ctx)

	logger.Debug().Msg("Applying oauth2_client_credentials strategy to authenticate request")

	cfg, ok := c.informer.Get()
	if !ok {
		return errorchain.NewWithMessage(
			pipeline.ErrInternal,
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

func (c *OAuth2ClientCredentials) init(ctx context.Context, appCtx app.Context) error {
	c.appCtx = appCtx

	if c.Header == nil {
		c.Header = &headerConfig{Name: "Authorization", Scheme: "Bearer"}
	}

	if len(c.AuthMethod) == 0 {
		c.AuthMethod = clientcredentials.AuthMethodBasicAuth
	}

	informer, err := secrets.NewCredentialsInformer(
		ctx,
		appCtx.SecretResolver(),
		secrets.Reference{Source: c.Credentials.Source, Selector: c.Credentials.Selector},
		secrets.WithConverter(c.createClientCredentialsConfig),
		secrets.WithUpdateCallback(func(_ context.Context, _ secrets.Credentials, cfg clientcredentials.Config) error {
			c.hash.Store(cfg.Hash())

			return nil
		}),
	)
	if err != nil {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed resolving oauth2 client credentials",
		).CausedBy(err)
	}

	c.informer = informer

	return nil
}

func (c *OAuth2ClientCredentials) createClientCredentialsConfig(
	creds secrets.Credentials,
) (clientcredentials.Config, error) {
	type credentials struct {
		ClientID     string `json:"client_id"     validate:"required"`
		ClientSecret string `json:"client_secret" validate:"required"`
	}

	var data credentials

	dec := c.appCtx.DecoderFactory().Decoder()
	if err := dec.DecodeMap(&data, creds.Values()); err != nil {
		return clientcredentials.Config{}, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed decoding oauth2 client credentials",
		).CausedBy(err)
	}

	return clientcredentials.Config{
		TokenURL:     c.TokenURL,
		ClientID:     data.ClientID,
		ClientSecret: data.ClientSecret,
		AuthMethod:   c.AuthMethod,
		Scopes:       c.Scopes,
		TTL:          c.TTL,
	}, nil
}
