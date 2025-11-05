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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/identity"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
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

type basicAuthAuthenticator struct {
	name     string
	id       string
	app      app.Context
	userID   string
	password string

	emptyAttributes map[string]any
	ads             extractors.HeaderValueExtractStrategy
}

func newBasicAuthAuthenticator(app app.Context, name string, rawConfig map[string]any) (types.Mechanism, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", AuthenticatorBasicAuth).
		Str("_name", name).
		Msg("Creating authenticator")

	type Config struct {
		UserID   string `mapstructure:"user_id"  validate:"required"`
		Password string `mapstructure:"password" validate:"required"`
	}

	var conf Config
	if err := decodeConfig(app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for basic_auth authenticator '%s'", name).CausedBy(err)
	}

	auth := basicAuthAuthenticator{
		name:            name,
		id:              name,
		app:             app,
		emptyAttributes: make(map[string]any),
		ads:             extractors.HeaderValueExtractStrategy{Name: "Authorization", Scheme: "Basic"},
	}

	// rewrite user id and password as hashes to mitigate potential side-channel attacks
	// during credentials check
	md := sha256.New()
	md.Write(stringx.ToBytes(conf.UserID))
	auth.userID = hex.EncodeToString(md.Sum(nil))

	md.Reset()
	md.Write(stringx.ToBytes(conf.Password))
	auth.password = hex.EncodeToString(md.Sum(nil))

	return &auth, nil
}

func (a *basicAuthAuthenticator) Execute(ctx heimdall.Context, sub identity.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", AuthenticatorBasicAuth).
		Str("_name", a.name).
		Str("_id", a.id).
		Msg("Executing authenticator")

	authData, err := a.ads.GetAuthData(ctx)
	if err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "expected header not present in request").
			WithErrorContext(a).
			CausedBy(err)
	}

	res, err := base64.StdEncoding.DecodeString(authData)
	if err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "failed to decode received credentials value").
			WithErrorContext(a)
	}

	userIDAndPassword := strings.Split(string(res), ":")
	if len(userIDAndPassword) != basicAuthSchemeCredentialsElements {
		return errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "malformed user-id - password scheme").
			WithErrorContext(a)
	}

	md := sha256.New()
	md.Write(stringx.ToBytes(userIDAndPassword[0]))
	userID := hex.EncodeToString(md.Sum(nil))

	md.Reset()
	md.Write(stringx.ToBytes(userIDAndPassword[1]))
	password := hex.EncodeToString(md.Sum(nil))

	userIDOK := userID == a.userID
	passwordOK := password == a.password

	if !userIDOK || !passwordOK {
		return errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "invalid user credentials").
			WithErrorContext(a)
	}

	sub["default"] = &identity.Principal{
		ID:         userIDAndPassword[0],
		Attributes: a.emptyAttributes,
	}

	return nil
}

func (a *basicAuthAuthenticator) CreateStep(def types.StepDefinition) (heimdall.Step, error) {
	if len(def.ID) == 0 && len(def.Config) == 0 {
		return a, nil
	}

	if len(def.Config) == 0 {
		auth := *a
		auth.id = def.ID

		return &auth, nil
	}

	type Config struct {
		UserID   string `mapstructure:"user_id"`
		Password string `mapstructure:"password"`
	}

	var conf Config
	if err := decodeConfig(a.app, def.Config, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for basic auth authenticator '%s'", a.name).CausedBy(err)
	}

	return &basicAuthAuthenticator{
		app:             a.app,
		name:            a.name,
		emptyAttributes: a.emptyAttributes,
		ads:             a.ads,
		id:              x.IfThenElse(len(def.ID) == 0, a.id, def.ID),
		userID: x.IfThenElseExec(len(conf.UserID) != 0,
			func() string {
				md := sha256.New()
				md.Write(stringx.ToBytes(conf.UserID))

				return hex.EncodeToString(md.Sum(nil))
			}, func() string {
				return a.userID
			}),
		password: x.IfThenElseExec(len(conf.Password) != 0,
			func() string {
				md := sha256.New()
				md.Write(stringx.ToBytes(conf.Password))

				return hex.EncodeToString(md.Sum(nil))
			}, func() string {
				return a.password
			}),
	}, nil
}

func (a *basicAuthAuthenticator) Kind() types.Kind { return types.KindAuthenticator }

func (a *basicAuthAuthenticator) Name() string { return a.name }

func (a *basicAuthAuthenticator) ID() string {
	return a.id
}

func (a *basicAuthAuthenticator) IsInsecure() bool { return false }
