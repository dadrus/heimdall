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
	"context"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	cc "github.com/dadrus/heimdall/internal/rules/oauth2/clientcredentials"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registry.Register(
		types.KindFinalizer,
		FinalizerOAuth2ClientCredentials,
		registry.FactoryFunc(newOAuth2ClientCredentialsFinalizer),
	)
}

type oauth2ClientCredentials struct {
	ClientID     string `json:"client_id"     validate:"required"`
	ClientSecret string `json:"client_secret" validate:"required"`
}

type oauth2ClientCredentialsHeaderConfig struct {
	Name   string `mapstructure:"name"   validate:"required"`
	Scheme string `mapstructure:"scheme"`
}

type oauth2ClientCredentialsFinalizer struct {
	name         string
	id           string
	app          app.Context
	cfg          cc.Config
	informer     *secrets.CredentialsInformer[oauth2ClientCredentials]
	headerName   string
	headerScheme string
}

func newOAuth2ClientCredentialsFinalizer(
	app app.Context,
	name string,
	rawConfig map[string]any,
) (types.Mechanism, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", FinalizerOAuth2ClientCredentials).
		Str("_name", name).
		Msg("Creating finalizer")

	type Config struct {
		TokenURL    string                               `mapstructure:"token_url"   validate:"required,url,enforced=istls"`             //nolint:lll
		Credentials config.Secret                        `mapstructure:"credentials" validate:"required"`                                //nolint:lll
		AuthMethod  cc.AuthMethod                        `mapstructure:"auth_method" validate:"omitempty,oneof=basic_auth request_body"` //nolint:lll
		Scopes      []string                             `mapstructure:"scopes"`
		TTL         *time.Duration                       `mapstructure:"cache_ttl"`
		Header      *oauth2ClientCredentialsHeaderConfig `mapstructure:"header"`
	}

	var conf Config
	if err := decodeConfig(app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"failed decoding config for oauth2_client_credentials finalizer '%s'",
			name,
		).CausedBy(err)
	}

	informer, err := secrets.NewCredentialsInformer(
		context.Background(),
		app.SecretResolver(),
		secrets.Reference{Source: conf.Credentials.Source, Selector: conf.Credentials.Selector},
		secrets.WithConverter(toOAuth2ClientCredentials(app.DecoderFactory())),
	)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed creating informer for client credentials",
		).CausedBy(err)
	}

	if strings.HasPrefix(conf.TokenURL, "http://") {
		logger.Warn().
			Str("_type", FinalizerOAuth2ClientCredentials).
			Str("_name", name).
			Msg("No TLS configured for the token_url used in finalizer")
	}

	return &oauth2ClientCredentialsFinalizer{
		name: name,
		id:   name,
		app:  app,
		cfg: cc.Config{
			TokenURL:   conf.TokenURL,
			AuthMethod: x.IfThenElse(len(conf.AuthMethod) == 0, cc.AuthMethodBasicAuth, conf.AuthMethod),
			Scopes:     conf.Scopes,
			TTL:        conf.TTL,
		},
		informer: informer,
		headerName: x.IfThenElseExec(
			conf.Header != nil,
			func() string { return conf.Header.Name },
			func() string { return "Authorization" },
		),
		headerScheme: x.IfThenElseExec(
			conf.Header != nil,
			func() string { return conf.Header.Scheme },
			func() string { return "" },
		),
	}, nil
}

func (f *oauth2ClientCredentialsFinalizer) Name() string            { return f.name }
func (f *oauth2ClientCredentialsFinalizer) ID() string              { return f.id }
func (f *oauth2ClientCredentialsFinalizer) Type() string            { return f.name }
func (*oauth2ClientCredentialsFinalizer) Accept(_ pipeline.Visitor) {}
func (*oauth2ClientCredentialsFinalizer) Kind() types.Kind          { return types.KindFinalizer }

func (f *oauth2ClientCredentialsFinalizer) CreateStep(
	_ context.Context,
	_ secrets.Resolver,
	def types.StepDefinition,
) (pipeline.Step, error) {
	if len(def.ID) == 0 && len(def.Config) == 0 {
		return f, nil
	}

	if len(def.Config) == 0 {
		fin := *f
		fin.id = def.ID

		return &fin, nil
	}

	type Config struct {
		TokenURL    *string                              `mapstructure:"token_url"   validate:"not_allowed"`
		Credentials *config.Secret                       `mapstructure:"credentials" validate:"not_allowed"`
		AuthMethod  *cc.AuthMethod                       `mapstructure:"auth_method" validate:"not_allowed"`
		Scopes      []string                             `mapstructure:"scopes"`
		TTL         *time.Duration                       `mapstructure:"cache_ttl"`
		Header      *oauth2ClientCredentialsHeaderConfig `mapstructure:"header"`
	}

	var conf Config
	if err := decodeConfig(f.app, def.Config, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"failed decoding config for oauth2_client_credentials finalizer '%s'",
			f.id,
		).CausedBy(err)
	}

	cfg := f.cfg
	cfg.TTL = x.IfThenElse(conf.TTL != nil, conf.TTL, cfg.TTL)
	cfg.Scopes = x.IfThenElse(conf.Scopes != nil, conf.Scopes, cfg.Scopes)

	return &oauth2ClientCredentialsFinalizer{
		name:     f.name,
		id:       x.IfThenElse(len(def.ID) == 0, f.id, def.ID),
		app:      f.app,
		informer: f.informer,
		cfg:      cfg,
		headerName: x.IfThenElseExec(
			conf.Header != nil,
			func() string { return conf.Header.Name },
			func() string { return f.headerName },
		),
		headerScheme: x.IfThenElseExec(
			conf.Header != nil,
			func() string { return conf.Header.Scheme },
			func() string { return f.headerScheme },
		),
	}, nil
}

func (f *oauth2ClientCredentialsFinalizer) Execute(ctx pipeline.Context, _ pipeline.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", FinalizerOAuth2ClientCredentials).
		Str("_name", f.name).
		Str("_id", f.id).
		Msg("Executing finalizer")

	creds, ok := f.informer.Get()
	if !ok {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"oauth2 client credentials are not available",
		)
	}

	cfg := f.cfg
	cfg.ClientID = creds.ClientID
	cfg.ClientSecret = creds.ClientSecret

	token, err := cfg.Token(ctx.Context())
	if err != nil {
		return err
	}

	headerScheme := token.TokenType
	if len(f.headerScheme) != 0 {
		headerScheme = f.headerScheme
	}

	ctx.AddHeaderForUpstream(f.headerName, headerScheme+" "+token.AccessToken)

	return nil
}

func toOAuth2ClientCredentials(
	df encoding.DecoderFactory,
) func(creds secrets.Credentials) (oauth2ClientCredentials, error) {
	return func(creds secrets.Credentials) (oauth2ClientCredentials, error) {
		var data oauth2ClientCredentials

		dec := df.Decoder()

		if err := dec.DecodeMap(&data, creds.Values()); err != nil {
			return oauth2ClientCredentials{}, errorchain.NewWithMessage(
				pipeline.ErrConfiguration,
				"failed decoding oauth2 client credentials",
			).CausedBy(err)
		}

		return data, nil
	}
}
