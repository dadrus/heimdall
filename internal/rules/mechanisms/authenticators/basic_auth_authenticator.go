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
	"context"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/secrets/informer"
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
	value [sha512.Size]byte
}

func newCredentialsChecker(userID, password string) credentialsChecker {
	return credentialsChecker{value: hash(userID, password)}
}

func (c credentialsChecker) check(userID, password string) error {
	value := hash(userID, password)

	if subtle.ConstantTimeCompare(c.value[:], value[:]) != 1 {
		return errorchain.NewWithMessage(
			pipeline.ErrAuthentication,
			"invalid user credentials",
		).
			CausedBy(pipeline.ErrAuthentication)
	}

	return nil
}

func hash(userID, password string) [sha512.Size]byte {
	md := sha512.New()
	md.Write(stringx.ToBytes(userID))
	md.Write(stringx.ToBytes(password))

	var result [sha512.Size]byte
	md.Sum(result[:0])

	return result
}

type authenticatorConfig struct {
	Credentials    *config.Secret `mapstructure:"credentials"`
	ErrorSignaling struct {
		Enabled *bool  `mapstructure:"enabled"`
		Realm   string `mapstructure:"realm"`
	} `mapstructure:"error_signaling"`
}

type basicAuthAuthenticator struct {
	name                  string
	id                    string
	principalName         string
	app                   app.Context
	resolver              *informer.CredentialsInformer[credentialsChecker]
	ownsResolver          bool
	realm                 string
	errorSignalingEnabled bool
	emptyAttributes       map[string]any
	ads                   extractors.HeaderValueExtractStrategy
}

func newBasicAuthAuthenticator(app app.Context, name string, rawConfig map[string]any) (types.Mechanism, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", AuthenticatorBasicAuth).
		Str("_name", name).
		Msg("Creating authenticator")

	var conf authenticatorConfig
	if err := decodeConfig(app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"failed decoding config for %s authenticator '%s'", AuthenticatorBasicAuth, name,
		).CausedBy(err)
	}

	resolver, err := createResolver(app, conf.Credentials)
	if err != nil {
		return nil, err
	}

	auth := basicAuthAuthenticator{
		name:            name,
		id:              name,
		app:             app,
		resolver:        resolver,
		principalName:   DefaultPrincipalName,
		emptyAttributes: make(map[string]any),
		ads:             extractors.HeaderValueExtractStrategy{Name: "Authorization", Scheme: "Basic"},
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

func createResolver(
	app app.Context,
	credentials *config.Secret,
) (*informer.CredentialsInformer[credentialsChecker], error) {
	if credentials == nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"credentials are required",
		)
	}

	resolver := &informer.CredentialsInformer[credentialsChecker]{
		Manager:   app.SecretsManager(),
		Reference: secrets.InternalRef(credentials.Source, credentials.Selector),
		Converter: toCredentialsChecker,
	}

	if err := resolver.Start(context.Background()); err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed resolving basic auth credentials",
		).CausedBy(err)
	}

	return resolver, nil
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
			NewWithMessage(
				pipeline.ErrAuthentication,
				"expected header not present in request",
			).
			WithErrorContext(a).
			CausedBy(err)
	}

	res, err := base64.StdEncoding.DecodeString(authData)
	if err != nil {
		return errorchain.
			NewWithMessage(
				pipeline.ErrAuthentication,
				"failed to decode received credentials value",
			).
			WithErrorContext(a)
	}

	userIDAndPassword := strings.Split(string(res), ":")
	if len(userIDAndPassword) != basicAuthSchemeCredentialsElements {
		return errorchain.
			NewWithMessage(
				pipeline.ErrAuthentication,
				"malformed user-id - password scheme",
			).
			WithErrorContext(a)
	}

	checker, ok := a.resolver.Get()
	if !ok {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"oauth2 client credentials are not available",
		)
	}

	if err = checker.check(userIDAndPassword[0], userIDAndPassword[1]); err != nil {
		return errorchain.NewWithMessage(
			pipeline.ErrAuthentication,
			"invalid user credentials",
		).
			WithErrorContext(a).
			CausedBy(err)
	}

	sub[a.principalName] = &pipeline.Principal{
		ID:         userIDAndPassword[0],
		Attributes: a.emptyAttributes,
	}

	return nil
}

func (a *basicAuthAuthenticator) CreateStep(def types.StepDefinition) (pipeline.Step, error) {
	if def.IsEmpty() {
		return a, nil
	}

	if len(def.Config) == 0 {
		auth := *a
		auth.id = x.IfThenElse(len(def.ID) == 0, a.id, def.ID)
		auth.principalName = x.IfThenElse(len(def.Principal) == 0, a.principalName, def.Principal)

		return &auth, nil
	}

	var (
		conf authenticatorConfig
		err  error
	)

	if err = decodeConfig(a.app, def.Config, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"failed decoding config for %s authenticator '%s'", AuthenticatorBasicAuth, a.name,
		).CausedBy(err)
	}

	resolver := a.resolver
	if conf.Credentials != nil {
		if resolver, err = createResolver(a.app, conf.Credentials); err != nil {
			return nil, err
		}
	}

	return &basicAuthAuthenticator{
		app:             a.app,
		name:            a.name,
		id:              x.IfThenElse(len(def.ID) == 0, a.id, def.ID),
		principalName:   x.IfThenElse(len(def.Principal) == 0, a.principalName, def.Principal),
		emptyAttributes: a.emptyAttributes,
		ads:             a.ads,
		resolver:        resolver,
		ownsResolver:    conf.Credentials != nil,
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

func (a *basicAuthAuthenticator) CleanUp(_ context.Context) {
	if !a.ownsResolver {
		return
	}

	a.resolver.Stop()
}

func (a *basicAuthAuthenticator) Name() string          { return a.name }
func (a *basicAuthAuthenticator) ID() string            { return a.id }
func (a *basicAuthAuthenticator) Type() string          { return a.name }
func (a *basicAuthAuthenticator) PrincipalName() string { return a.principalName }
func (*basicAuthAuthenticator) Kind() types.Kind        { return types.KindAuthenticator }
func (*basicAuthAuthenticator) IsInsecure() bool        { return false }

func toCredentialsChecker(creds secrets.Credentials) (credentialsChecker, error) {
	type credentials struct {
		UserID   string `mapstructure:"user_id"  validate:"required"`
		Password string `mapstructure:"password" validate:"required"`
	}

	var data credentials
	if err := creds.Decode(&data); err != nil {
		return credentialsChecker{}, err
	}

	return newCredentialsChecker(data.UserID, data.Password), nil
}
