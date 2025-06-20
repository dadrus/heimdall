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
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
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
	registerTypeFactory(
		func(app app.Context, id string, typ string, conf map[string]any) (bool, Authenticator, error) {
			if typ != AuthenticatorBasicAuth {
				return false, nil, nil
			}

			auth, err := newBasicAuthAuthenticator(app, id, conf)

			return true, auth, err
		})
}

type basicAuthAuthenticator struct {
	id                   string
	app                  app.Context
	userID               string
	password             string
	allowFallbackOnError bool
}

func newBasicAuthAuthenticator(
	app app.Context,
	id string,
	rawConfig map[string]any,
) (*basicAuthAuthenticator, error) {
	logger := app.Logger()
	logger.Info().Str("_id", id).Msg("Creating basic auth authenticator")

	type Config struct {
		UserID               string `mapstructure:"user_id"                 validate:"required"`
		Password             string `mapstructure:"password"                validate:"required"`
		AllowFallbackOnError bool   `mapstructure:"allow_fallback_on_error"`
	}

	var conf Config
	if err := decodeConfig(app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for basic auth authenticator '%s'", id).CausedBy(err)
	}

	if conf.AllowFallbackOnError {
		logger.Warn().Str("_id", id).Msg("Usage of allow_fallback_on_error is deprecated and has no effect")
	}

	auth := basicAuthAuthenticator{
		id:                   id,
		app:                  app,
		allowFallbackOnError: conf.AllowFallbackOnError,
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

func (a *basicAuthAuthenticator) Execute(ctx heimdall.RequestContext) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().Str("_id", a.id).Msg("Authenticating using basic_auth authenticator")

	strategy := extractors.HeaderValueExtractStrategy{Name: "Authorization", Scheme: "Basic"}

	authData, err := strategy.GetAuthData(ctx)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "expected header not present in request").
			WithErrorContext(a).
			CausedBy(err)
	}

	res, err := base64.StdEncoding.DecodeString(authData)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "failed to decode received credentials value").
			WithErrorContext(a)
	}

	userIDAndPassword := strings.Split(string(res), ":")
	if len(userIDAndPassword) != basicAuthSchemeCredentialsElements {
		return nil, errorchain.
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
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "invalid user credentials").
			WithErrorContext(a)
	}

	return &subject.Subject{ID: userIDAndPassword[0], Attributes: make(map[string]any)}, nil
}

func (a *basicAuthAuthenticator) WithConfig(stepID string, rawConfig map[string]any) (Authenticator, error) {
	// this authenticator allows full redefinition on the rule level
	if len(rawConfig) == 0 {
		return a, nil
	}

	type Config struct {
		UserID               string `mapstructure:"user_id"`
		Password             string `mapstructure:"password"`
		AllowFallbackOnError *bool  `mapstructure:"allow_fallback_on_error"`
	}

	var conf Config
	if err := decodeConfig(a.app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for basic auth authenticator '%s'", a.id).CausedBy(err)
	}

	if conf.AllowFallbackOnError != nil {
		logger := a.app.Logger()
		logger.Warn().Str("_id", a.id).
			Msg("Usage of allow_fallback_on_error is deprecated and has no effect")
	}

	return &basicAuthAuthenticator{
		id:  a.id,
		app: a.app,
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
		allowFallbackOnError: x.IfThenElseExec(conf.AllowFallbackOnError != nil,
			func() bool { return *conf.AllowFallbackOnError },
			func() bool { return a.allowFallbackOnError }),
	}, nil
}

func (a *basicAuthAuthenticator) ID() string {
	return a.id
}

func (a *basicAuthAuthenticator) IsInsecure() bool { return false }
