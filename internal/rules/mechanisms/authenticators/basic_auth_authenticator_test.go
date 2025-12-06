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
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/identity"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/validation"
)

func TestNewBasicAuthAuthenticator(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config config.MechanismConfig
		assert func(t *testing.T, err error, auth *basicAuthAuthenticator)
	}{
		"valid configuration": {
			config: config.MechanismConfig{"user_id": "foo", "password": "bar"},
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				md := sha256.New()
				md.Write([]byte("foo"))
				userID := hex.EncodeToString(md.Sum(nil))

				md.Reset()
				md.Write([]byte("bar"))
				password := hex.EncodeToString(md.Sum(nil))

				assert.Equal(t, userID, auth.userID)
				assert.Equal(t, password, auth.password)
				assert.Equal(t, "valid configuration", auth.ID())
				assert.Equal(t, auth.ID(), auth.Name())
				assert.Empty(t, auth.emptyAttributes)
				assert.NotNil(t, auth.emptyAttributes)
				assert.False(t, auth.IsInsecure())
				assert.Equal(t, DefaultPrincipalName, auth.PrincipalName())
				assert.Equal(t, types.KindAuthenticator, auth.Kind())
			},
		},
		"without user_id": {
			config: config.MechanismConfig{"password": "bar"},
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)

				assert.Nil(t, auth)
			},
		},
		"without password": {
			config: config.MechanismConfig{"user_id": "foo"},
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)

				assert.Nil(t, auth)
			},
		},
		"with unexpected config attribute": {
			config: config.MechanismConfig{"user_id": "foo", "password": "bar", "foo": "bar"},
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotNil(t, auth)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			// WHEN
			mech, err := newBasicAuthAuthenticator(appCtx, uc, tc.config)

			// THEN
			auth, ok := mech.(*basicAuthAuthenticator)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, auth)
		})
	}
}

func TestBasicAuthAuthenticatorCreateStep(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config  config.MechanismConfig
		stepDef types.StepDefinition
		assert  func(t *testing.T, err error, prototype, configured *basicAuthAuthenticator)
	}{
		"no new configuration for the configured authenticator": {
			config: config.MechanismConfig{"user_id": "foo", "password": "bar"},
			assert: func(t *testing.T, err error, prototype, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "no new configuration for the configured authenticator", configured.ID())
			},
		},
		"password differs": {
			config:  config.MechanismConfig{"user_id": "foo", "password": "bar"},
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"user_id": "foo", "password": "baz"}},
			assert: func(t *testing.T, err error, prototype, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)

				assert.Equal(t, prototype.userID, configured.userID)
				assert.NotEqual(t, prototype.password, configured.password)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, "password differs", configured.ID())
				assert.Equal(t, prototype.emptyAttributes, configured.emptyAttributes)
				assert.Equal(t, prototype.PrincipalName(), configured.PrincipalName())
				assert.False(t, configured.IsInsecure())
				assert.Equal(t, types.KindAuthenticator, configured.Kind())
			},
		},
		"no user_id provided": {
			config:  config.MechanismConfig{"user_id": "foo", "password": "bar"},
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"password": "baz"}},
			assert: func(t *testing.T, err error, prototype, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)

				assert.Equal(t, prototype.userID, configured.userID)
				assert.NotEqual(t, prototype.password, configured.password)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, "no user_id provided", configured.ID())
				assert.Equal(t, prototype.emptyAttributes, configured.emptyAttributes)
				assert.Equal(t, prototype.PrincipalName(), configured.PrincipalName())
				assert.False(t, configured.IsInsecure())
				assert.Equal(t, types.KindAuthenticator, configured.Kind())
			},
		},
		"no password provided": {
			config:  config.MechanismConfig{"user_id": "foo", "password": "bar"},
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"user_id": "baz"}},
			assert: func(t *testing.T, err error, prototype, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)

				assert.NotEqual(t, prototype.userID, configured.userID)
				assert.Equal(t, prototype.password, configured.password)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, "no password provided", configured.ID())
				assert.Equal(t, prototype.emptyAttributes, configured.emptyAttributes)
				assert.Equal(t, prototype.PrincipalName(), configured.PrincipalName())
				assert.False(t, configured.IsInsecure())
				assert.Equal(t, types.KindAuthenticator, configured.Kind())
			},
		},
		"user_id differs": {
			config:  config.MechanismConfig{"user_id": "foo", "password": "bar"},
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"user_id": "baz", "password": "bar"}},
			assert: func(t *testing.T, err error, prototype, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)

				assert.NotEqual(t, prototype.userID, configured.userID)
				assert.Equal(t, prototype.password, configured.password)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, "user_id differs", configured.ID())
				assert.Equal(t, prototype.emptyAttributes, configured.emptyAttributes)
				assert.Equal(t, prototype.PrincipalName(), configured.PrincipalName())
				assert.False(t, configured.IsInsecure())
				assert.Equal(t, types.KindAuthenticator, configured.Kind())
			},
		},
		"user_id and password differs": {
			config:  config.MechanismConfig{"user_id": "foo", "password": "bar"},
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"user_id": "baz", "password": "baz"}},
			assert: func(t *testing.T, err error, prototype, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)

				assert.NotEqual(t, prototype.userID, configured.userID)
				assert.NotEqual(t, prototype.password, configured.password)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.Equal(t, "user_id and password differs", configured.ID())
				assert.Equal(t, prototype.emptyAttributes, configured.emptyAttributes)
				assert.Equal(t, prototype.PrincipalName(), configured.PrincipalName())
				assert.False(t, configured.IsInsecure())
				assert.Equal(t, types.KindAuthenticator, configured.Kind())

				md := sha256.New()
				md.Write([]byte("baz"))
				value := hex.EncodeToString(md.Sum(nil))

				assert.Equal(t, value, configured.userID)
				assert.Equal(t, value, configured.password)
			},
		},
		"only step id configured": {
			config:  config.MechanismConfig{"user_id": "foo", "password": "bar"},
			stepDef: types.StepDefinition{ID: "foo"},
			assert: func(t *testing.T, err error, prototype, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				require.Equal(t, prototype.Name(), configured.Name())
				require.NotEqual(t, prototype.ID(), configured.ID())
				require.Equal(t, "foo", configured.ID())
				require.Equal(t, prototype.userID, configured.userID)
				require.Equal(t, prototype.password, configured.password)
				require.Equal(t, prototype.ads, configured.ads)
				require.Equal(t, prototype.app, configured.app)
				require.Equal(t, prototype.emptyAttributes, configured.emptyAttributes)
				assert.Equal(t, prototype.PrincipalName(), configured.PrincipalName())
				assert.False(t, configured.IsInsecure())
				assert.Equal(t, types.KindAuthenticator, configured.Kind())
			},
		},
		"only principal name configured": {
			config:  config.MechanismConfig{"user_id": "foo", "password": "bar"},
			stepDef: types.StepDefinition{Principal: "foo"},
			assert: func(t *testing.T, err error, prototype, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				require.Equal(t, prototype.Name(), configured.Name())
				require.Equal(t, prototype.ID(), configured.ID())
				require.Equal(t, prototype.userID, configured.userID)
				require.Equal(t, prototype.password, configured.password)
				require.Equal(t, prototype.ads, configured.ads)
				require.Equal(t, prototype.app, configured.app)
				require.Equal(t, prototype.emptyAttributes, configured.emptyAttributes)
				assert.NotEqual(t, prototype.PrincipalName(), configured.PrincipalName())
				assert.Equal(t, "foo", configured.PrincipalName())
				assert.False(t, configured.IsInsecure())
				assert.Equal(t, types.KindAuthenticator, configured.Kind())
			},
		},
		"malformed step configuration": {
			config:  config.MechanismConfig{"user_id": "foo", "password": "bar"},
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"user_id": "baz", "password": 1}},
			assert: func(t *testing.T, err error, _, _ *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			mech, err := newBasicAuthAuthenticator(appCtx, uc, tc.config)
			require.NoError(t, err)

			configured, ok := mech.(*basicAuthAuthenticator)
			require.True(t, ok)

			// WHEN
			step, err := mech.CreateStep(tc.stepDef)

			// THEN
			auth, ok := step.(*basicAuthAuthenticator)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, configured, auth)
		})
	}
}

func TestBasicAuthAuthenticatorExecute(t *testing.T) {
	t.Parallel()

	type HandlerIdentifier interface {
		ID() string
	}

	conf := config.MechanismConfig{"user_id": "foo", "password": "bar"}

	for uc, tc := range map[string]struct {
		stepDef          types.StepDefinition
		configureContext func(t *testing.T, ctx *mocks.ContextMock)
		assert           func(t *testing.T, err error, sub identity.Subject)
	}{
		"no required header present": {
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("Authorization").Return("")

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub identity.Subject) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.ErrorIs(t, err, heimdall.ErrArgument)
				require.ErrorContains(t, err, "expected header not present")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "no required header present", identifier.ID())

				assert.Empty(t, sub)
			},
		},
		"base64 decoding error": {
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("Authorization").Return("Basic bar")

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub identity.Subject) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.NotErrorIs(t, err, heimdall.ErrArgument)
				require.ErrorContains(t, err, "failed to decode")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "base64 decoding error", identifier.ID())

				assert.Empty(t, sub)
			},
		},
		"malformed encoding": {
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("Authorization").
					Return("Basic " + base64.StdEncoding.EncodeToString([]byte("foo|bar")))

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub identity.Subject) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.NotErrorIs(t, err, heimdall.ErrArgument)
				require.ErrorContains(t, err, "malformed user-id - password")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "malformed encoding", identifier.ID())

				assert.Empty(t, sub)
			},
		},
		"invalid user id": {
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("Authorization").
					Return("Basic " + base64.StdEncoding.EncodeToString([]byte("baz:bar")))

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub identity.Subject) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.NotErrorIs(t, err, heimdall.ErrArgument)
				require.Contains(t, err.Error(), "invalid user credentials")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "invalid user id", identifier.ID())

				assert.Empty(t, sub)
			},
		},
		"invalid password": {
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("Authorization").
					Return("Basic " + base64.StdEncoding.EncodeToString([]byte("foo:baz")))

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub identity.Subject) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.NotErrorIs(t, err, heimdall.ErrArgument)
				require.ErrorContains(t, err, "invalid user credentials")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "invalid password", identifier.ID())

				assert.Empty(t, sub)
			},
		},
		"default principal is created for valid credentials": {
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("Authorization").
					Return("Basic " + base64.StdEncoding.EncodeToString([]byte("foo:bar")))

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub identity.Subject) {
				t.Helper()

				require.NoError(t, err)

				require.Equal(t, "foo", sub.ID())
				assert.NotNil(t, sub.Attributes())
				assert.Empty(t, sub.Attributes())
			},
		},
		"custom principal is created for valid credentials": {
			stepDef: types.StepDefinition{Principal: "baz"},
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("Authorization").
					Return("Basic " + base64.StdEncoding.EncodeToString([]byte("foo:bar")))

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub identity.Subject) {
				t.Helper()

				require.NoError(t, err)

				assert.Empty(t, sub.ID())
				assert.Empty(t, sub.Attributes())
				assert.NotNil(t, sub["baz"])
				assert.Equal(t, "foo", sub["baz"].ID)
				assert.Empty(t, sub["baz"].Attributes)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			mech, err := newBasicAuthAuthenticator(appCtx, uc, conf)
			require.NoError(t, err)

			step, err := mech.CreateStep(tc.stepDef)
			require.NoError(t, err)

			ctx := mocks.NewContextMock(t)
			ctx.EXPECT().Context().Return(t.Context())
			tc.configureContext(t, ctx)

			sub := make(identity.Subject)

			// WHEN
			err = step.Execute(ctx, sub)

			// THEN
			tc.assert(t, err, sub)
		})
	}
}

func TestBasicAuthAuthenticatorAccept(t *testing.T) {
	t.Parallel()

	// GIVEN
	auth := &basicAuthAuthenticator{}
	visitor := mocks.NewVisitorMock(t)

	visitor.EXPECT().VisitInsecure(auth)
	visitor.EXPECT().VisitPrincipalNamer(auth)

	// WHEN
	auth.Accept(visitor)

	// THEN expected calls are done
}
