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

package authenticators

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/alexedwards/argon2id"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/httpx"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

const (
	basicAuthSchemeCredentialsElements = 2
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registry.Register(
		types.KindAuthenticator,
		AuthenticatorBasicAuth,
		registry.FactoryFunc(newBasicAuthAuthenticator),
	)
}

// credentialsChecker is used to check user credentials.
//
// It is used to mitigate potential side-channel attacks during credentials check.
// Note: it does not correspond to security best practices and does not use a proper
// key derivation/password hash function, like SCrypt or Argon2. This will be
// implemented later.
type credentialsChecker struct {
	UserID   string `json:"user_id"  validate:"required"`
	Password string `json:"password" validate:"required"`
}

func (c credentialsChecker) check(userID, password string) error {
	match, _ := argon2id.ComparePasswordAndHash(password, c.Password)
	res := subtle.ConstantTimeCompare(stringx.ToBytes(userID), stringx.ToBytes(c.UserID))

	match = match && res == 1

	if !match {
		return errorchain.NewWithMessage(
			pipeline.ErrAuthentication,
			"invalid user credentials",
		).CausedBy(pipeline.ErrAuthentication)
	}

	return nil
}

type basicAuthAuthenticator struct {
	name                  string
	id                    string
	principalName         string
	app                   app.Context
	realm                 string
	errorSignalingEnabled bool
	emptyAttributes       map[string]any
	ads                   extractors.HeaderValueExtractStrategy
	informer              *secrets.CredentialsInformer[credentialsChecker]
}

func newBasicAuthAuthenticator(app app.Context, name string, rawConfig map[string]any) (types.Mechanism, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", AuthenticatorBasicAuth).
		Str("_name", name).
		Msg("Creating authenticator")

	type authenticatorConfig struct {
		Credentials    config.Secret `mapstructure:"credentials"`
		ErrorSignaling struct {
			Enabled *bool  `mapstructure:"enabled"`
			Realm   string `mapstructure:"realm"`
		} `mapstructure:"error_signaling"`
	}

	var conf authenticatorConfig
	if err := decodeConfig(app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"failed decoding config for %s authenticator '%s'", AuthenticatorBasicAuth, name,
		).CausedBy(err)
	}

	informer, err := secrets.NewCredentialsInformer(
		app.SecretResolver(),
		secrets.Reference{Source: conf.Credentials.Source, Selector: conf.Credentials.Selector},
		secrets.WithConverter(toCredentialsChecker(app.DecoderFactory())),
	)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed creating credentials informer",
		).CausedBy(err)
	}

	auth := basicAuthAuthenticator{
		name:            name,
		id:              name,
		app:             app,
		principalName:   DefaultPrincipalName,
		emptyAttributes: make(map[string]any),
		ads:             extractors.HeaderValueExtractStrategy{Name: "Authorization", Scheme: "Basic"},
		informer:        informer,
		errorSignalingEnabled: x.IfThenElseExec(
			conf.ErrorSignaling.Enabled != nil,
			func() bool { return *conf.ErrorSignaling.Enabled },
			func() bool { return false },
		),
		realm: x.IfThenElse(
			len(conf.ErrorSignaling.Realm) != 0,
			conf.ErrorSignaling.Realm,
			defaultAuthenticationRealm,
		),
	}

	return &auth, nil
}

func (a *basicAuthAuthenticator) Accept(visitor pipeline.Visitor) {
	visitor.VisitInsecure(a)
	visitor.VisitPrincipalNamer(a)
}

func (a *basicAuthAuthenticator) Execute(ctx pipeline.Context, sub pipeline.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", AuthenticatorBasicAuth).
		Str("_name", a.name).
		Str("_id", a.id).
		Msg("Executing authenticator")

	authData, err := a.ads.GetAuthData(ctx)
	if err != nil {
		return errorchain.
			NewWithMessage(pipeline.ErrAuthentication, "expected header not present in request").
			WithAspects(a).
			CausedBy(err)
	}

	res, err := base64.StdEncoding.DecodeString(authData)
	if err != nil {
		return errorchain.
			NewWithMessage(pipeline.ErrAuthentication, "failed to decode received credentials value").
			WithAspects(a)
	}

	userIDAndPassword := strings.Split(string(res), ":")
	if len(userIDAndPassword) != basicAuthSchemeCredentialsElements {
		return errorchain.
			NewWithMessage(pipeline.ErrAuthentication, "malformed user-id - password scheme").
			WithAspects(a)
	}

	checker, ok := a.informer.Get()
	if !ok {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"basic auth credentials are not available",
		)
	}

	if err = checker.check(userIDAndPassword[0], userIDAndPassword[1]); err != nil {
		return errorchain.NewWithMessage(pipeline.ErrAuthentication, "invalid user credentials").
			WithAspects(a).
			CausedBy(err)
	}

	sub[a.principalName] = &pipeline.Principal{
		ID:         userIDAndPassword[0],
		Attributes: a.emptyAttributes,
	}

	return nil
}

func (a *basicAuthAuthenticator) CreateStep(
	resolver secrets.Resolver,
	def types.StepDefinition,
) (pipeline.Step, error) {
	if def.IsEmpty() {
		return a, nil
	}

	if len(def.Config) == 0 {
		auth := *a
		auth.id = x.IfThenElse(len(def.ID) == 0, a.id, def.ID)
		auth.principalName = x.IfThenElse(len(def.Principal) == 0, a.principalName, def.Principal)

		return &auth, nil
	}

	type authenticatorConfig struct {
		Credentials    *config.Secret `mapstructure:"credentials"`
		ErrorSignaling struct {
			Enabled *bool  `mapstructure:"enabled"`
			Realm   string `mapstructure:"realm"`
		} `mapstructure:"error_signaling"`
	}

	var conf authenticatorConfig
	if err := decodeConfig(a.app, def.Config, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"failed decoding config for %s authenticator '%s'", AuthenticatorBasicAuth, a.name,
		).CausedBy(err)
	}

	informer := a.informer

	if conf.Credentials != nil {
		var err error

		informer, err = secrets.NewCredentialsInformer(
			resolver,
			secrets.Reference{Source: conf.Credentials.Source, Selector: conf.Credentials.Selector},
			secrets.WithConverter(toCredentialsChecker(a.app.DecoderFactory())),
		)
		if err != nil {
			return nil, errorchain.NewWithMessage(
				pipeline.ErrConfiguration,
				"failed creating credentials informer",
			).CausedBy(err)
		}
	}

	return &basicAuthAuthenticator{
		app:             a.app,
		name:            a.name,
		id:              x.IfThenElse(len(def.ID) == 0, a.id, def.ID),
		principalName:   x.IfThenElse(len(def.Principal) == 0, a.principalName, def.Principal),
		emptyAttributes: a.emptyAttributes,
		ads:             a.ads,
		informer:        informer,
		errorSignalingEnabled: x.IfThenElseExec(
			conf.ErrorSignaling.Enabled != nil,
			func() bool { return *conf.ErrorSignaling.Enabled },
			func() bool { return a.errorSignalingEnabled },
		),
		realm: x.IfThenElse(
			len(conf.ErrorSignaling.Realm) == 0,
			a.realm,
			conf.ErrorSignaling.Realm,
		),
	}, nil
}

func (a *basicAuthAuthenticator) DecorateErrorResponse(_ error, er *pipeline.ErrorResponse) {
	if !a.errorSignalingEnabled {
		return
	}

	er.Code = http.StatusUnauthorized

	er.AddHeader(wwwAuthenticateHeader,
		httpx.NewHeader(
			httpx.WithPrefix("Basic"),
			httpx.WithKeyValue("realm", a.realm),
		),
	)
}

func (a *basicAuthAuthenticator) Name() string          { return a.name }
func (a *basicAuthAuthenticator) ID() string            { return a.id }
func (a *basicAuthAuthenticator) Type() string          { return a.name }
func (a *basicAuthAuthenticator) PrincipalName() string { return a.principalName }
func (*basicAuthAuthenticator) Kind() types.Kind        { return types.KindAuthenticator }
func (*basicAuthAuthenticator) IsInsecure() bool        { return false }

func toCredentialsChecker(df encoding.DecoderFactory) func(creds secrets.Credentials) (credentialsChecker, error) {
	return func(creds secrets.Credentials) (credentialsChecker, error) {
		var data credentialsChecker
		if err := df.Decoder().DecodeMap(&data, creds.Values()); err != nil {
			return credentialsChecker{}, err
		}

		return data, nil
	}
}
