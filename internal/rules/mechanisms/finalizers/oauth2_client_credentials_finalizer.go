// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package finalizers

import (
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/oauth2/clientcredentials"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(app app.Context, id string, typ string, conf map[string]any) (bool, Finalizer, error) {
			if typ != FinalizerOAuth2ClientCredentials {
				return false, nil, nil
			}

			finalizer, err := newOAuth2ClientCredentialsFinalizer(app, id, conf)

			return true, finalizer, err
		})
}

type oauth2ClientCredentialsFinalizer struct {
	id           string
	app          app.Context
	cfg          clientcredentials.Config
	headerName   string
	headerScheme string
}

func newOAuth2ClientCredentialsFinalizer(
	app app.Context,
	id string,
	rawConfig map[string]any,
) (*oauth2ClientCredentialsFinalizer, error) {
	logger := app.Logger()
	logger.Info().Str("_id", id).Msg("Creating oauth2_client_credentials finalizer")

	type HeaderConfig struct {
		Name   string `mapstructure:"name"   validate:"required"`
		Scheme string `mapstructure:"scheme"`
	}

	type Config struct {
		clientcredentials.Config `mapstructure:",squash"`
		Header                   *HeaderConfig `mapstructure:"header"`
	}

	var conf Config
	if err := decodeConfig(app.Validator(), rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for oauth2_client_credentials finalizer '%s'", id).CausedBy(err)
	}

	if strings.HasPrefix(conf.TokenURL, "http://") {
		logger.Warn().Str("_id", id).
			Msg("No TLS configured for the token_url used in oauth2_client_credentials finalizer")
	}

	conf.AuthMethod = x.IfThenElse(
		len(conf.AuthMethod) == 0,
		clientcredentials.AuthMethodBasicAuth,
		clientcredentials.AuthMethodRequestBody,
	)

	return &oauth2ClientCredentialsFinalizer{
		id:  id,
		app: app,
		cfg: conf.Config,
		headerName: x.IfThenElseExec(conf.Header != nil,
			func() string { return conf.Header.Name },
			func() string { return "Authorization" }),
		headerScheme: x.IfThenElseExec(conf.Header != nil,
			func() string { return conf.Header.Scheme },
			func() string { return "" }),
	}, nil
}

func (f *oauth2ClientCredentialsFinalizer) ContinueOnError() bool { return false }
func (f *oauth2ClientCredentialsFinalizer) ID() string            { return f.id }

func (f *oauth2ClientCredentialsFinalizer) WithConfig(rawConfig map[string]any) (Finalizer, error) {
	type HeaderConfig struct {
		Name   string `mapstructure:"name"   validate:"required"`
		Scheme string `mapstructure:"scheme"`
	}

	type Config struct {
		Scopes []string       `mapstructure:"scopes"`
		TTL    *time.Duration `mapstructure:"cache_ttl"`
		Header *HeaderConfig  `mapstructure:"header"`
	}

	var conf Config
	if err := decodeConfig(f.app.Validator(), rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for oauth2_client_credentials finalizer '%s'", f.id).CausedBy(err)
	}

	cfg := f.cfg
	cfg.TTL = x.IfThenElse(conf.TTL != nil, conf.TTL, cfg.TTL)
	cfg.Scopes = x.IfThenElse(conf.Scopes != nil, conf.Scopes, cfg.Scopes)

	return &oauth2ClientCredentialsFinalizer{
		id:  f.id,
		app: f.app,
		cfg: cfg,
		headerName: x.IfThenElseExec(conf.Header != nil,
			func() string { return conf.Header.Name },
			func() string { return f.headerName }),
		headerScheme: x.IfThenElseExec(conf.Header != nil && len(conf.Header.Scheme) != 0,
			func() string { return conf.Header.Scheme },
			func() string { return f.headerScheme }),
	}, nil
}

func (f *oauth2ClientCredentialsFinalizer) Execute(ctx heimdall.RequestContext, _ *subject.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().Msg("Finalizing using oauth2_client_credentials finalizer")

	token, err := f.cfg.Token(ctx.Context())
	if err != nil {
		return err
	}

	headerScheme := token.TokenType
	if len(f.headerScheme) != 0 {
		headerScheme = f.headerScheme
	}

	ctx.AddHeaderForUpstream(f.headerName, fmt.Sprintf("%s %s", headerScheme, token.AccessToken))

	return nil
}
