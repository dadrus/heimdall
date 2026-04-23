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
	"net/http"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/pipeline/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/validation"
)

func TestNewBasicAuthAuthenticator(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config config.MechanismConfig
		assert func(t *testing.T, err error, auth *basicAuthAuthenticator)
	}{
		"valid configuration without error signaling": {
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
				assert.Equal(t, "valid configuration without error signaling", auth.ID())
				assert.Equal(t, auth.ID(), auth.Name())
				assert.Empty(t, auth.emptyAttributes)
				assert.NotNil(t, auth.emptyAttributes)
				assert.Equal(t, defaultAuthenticationRealm, auth.realm)
				assert.False(t, auth.errorSignalingEnabled)
				assert.False(t, auth.IsInsecure())
				assert.Equal(t, DefaultPrincipalName, auth.PrincipalName())
				assert.Equal(t, types.KindAuthenticator, auth.Kind())
				assert.Equal(t, auth.ID(), auth.Type())
			},
		},
		"valid configuration with error signaling and default realm": {
			config: config.MechanismConfig{
				"user_id":         "foo",
				"password":        "bar",
				"error_signaling": map[string]any{"enabled": true},
			},
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
				assert.Equal(t, "valid configuration with error signaling and default realm", auth.ID())
				assert.Equal(t, auth.ID(), auth.Name())
				assert.Empty(t, auth.emptyAttributes)
				assert.NotNil(t, auth.emptyAttributes)
				assert.Equal(t, defaultAuthenticationRealm, auth.realm)
				assert.True(t, auth.errorSignalingEnabled)
				assert.False(t, auth.IsInsecure())
				assert.Equal(t, DefaultPrincipalName, auth.PrincipalName())
				assert.Equal(t, types.KindAuthenticator, auth.Kind())
				assert.Equal(t, auth.ID(), auth.Type())
			},
		},
		"valid configuration with error signaling and custom realm": {
			config: config.MechanismConfig{
				"user_id":  "foo",
				"password": "bar",
				"error_signaling": map[string]any{
					"enabled": true,
					"realm":   "custom",
				},
			},
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
				assert.Equal(t, "valid configuration with error signaling and custom realm", auth.ID())
				assert.Equal(t, auth.ID(), auth.Name())
				assert.Empty(t, auth.emptyAttributes)
				assert.NotNil(t, auth.emptyAttributes)
				assert.Equal(t, "custom", auth.realm)
				assert.True(t, auth.errorSignalingEnabled)
				assert.False(t, auth.IsInsecure())
				assert.Equal(t, DefaultPrincipalName, auth.PrincipalName())
				assert.Equal(t, types.KindAuthenticator, auth.Kind())
				assert.Equal(t, auth.ID(), auth.Type())
			},
		},
		"without user_id": {
			config: config.MechanismConfig{"password": "bar"},
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)

				assert.Nil(t, auth)
			},
		},
		"without password": {
			config: config.MechanismConfig{"user_id": "foo"},
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)

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
				assert.Equal(t, prototype.realm, configured.realm)
				assert.Equal(t, defaultAuthenticationRealm, configured.realm)
				assert.False(t, configured.errorSignalingEnabled)
				assert.Equal(t, prototype.PrincipalName(), configured.PrincipalName())
				assert.False(t, configured.IsInsecure())
				assert.Equal(t, types.KindAuthenticator, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
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
				assert.Equal(t, prototype.realm, configured.realm)
				assert.Equal(t, defaultAuthenticationRealm, configured.realm)
				assert.False(t, configured.errorSignalingEnabled)
				assert.Equal(t, prototype.PrincipalName(), configured.PrincipalName())
				assert.False(t, configured.IsInsecure())
				assert.Equal(t, types.KindAuthenticator, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
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
				assert.Equal(t, prototype.realm, configured.realm)
				assert.Equal(t, defaultAuthenticationRealm, configured.realm)
				assert.False(t, configured.errorSignalingEnabled)
				assert.Equal(t, prototype.PrincipalName(), configured.PrincipalName())
				assert.False(t, configured.IsInsecure())
				assert.Equal(t, types.KindAuthenticator, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
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
				assert.Equal(t, prototype.realm, configured.realm)
				assert.Equal(t, defaultAuthenticationRealm, configured.realm)
				assert.False(t, configured.errorSignalingEnabled)
				assert.Equal(t, prototype.PrincipalName(), configured.PrincipalName())
				assert.False(t, configured.IsInsecure())
				assert.Equal(t, types.KindAuthenticator, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
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
				assert.Equal(t, prototype.realm, configured.realm)
				assert.Equal(t, defaultAuthenticationRealm, configured.realm)
				assert.False(t, configured.errorSignalingEnabled)
				assert.Equal(t, prototype.PrincipalName(), configured.PrincipalName())
				assert.False(t, configured.IsInsecure())
				assert.Equal(t, types.KindAuthenticator, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())

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
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.NotEqual(t, prototype.ID(), configured.ID())
				assert.Equal(t, "foo", configured.ID())
				assert.Equal(t, prototype.userID, configured.userID)
				assert.Equal(t, prototype.password, configured.password)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.app, configured.app)
				assert.Equal(t, prototype.emptyAttributes, configured.emptyAttributes)
				assert.Equal(t, prototype.realm, configured.realm)
				assert.Equal(t, defaultAuthenticationRealm, configured.realm)
				assert.False(t, configured.errorSignalingEnabled)
				assert.Equal(t, prototype.PrincipalName(), configured.PrincipalName())
				assert.False(t, configured.IsInsecure())
				assert.Equal(t, types.KindAuthenticator, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
			},
		},
		"only principal name configured": {
			config: config.MechanismConfig{
				"user_id":         "foo",
				"password":        "bar",
				"error_signaling": map[string]any{"enabled": true},
			},
			stepDef: types.StepDefinition{Principal: "foo"},
			assert: func(t *testing.T, err error, prototype, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.Equal(t, prototype.userID, configured.userID)
				assert.Equal(t, prototype.password, configured.password)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.app, configured.app)
				assert.Equal(t, prototype.emptyAttributes, configured.emptyAttributes)
				assert.Equal(t, prototype.realm, configured.realm)
				assert.Equal(t, defaultAuthenticationRealm, configured.realm)
				assert.True(t, configured.errorSignalingEnabled)
				assert.NotEqual(t, prototype.PrincipalName(), configured.PrincipalName())
				assert.Equal(t, "foo", configured.PrincipalName())
				assert.False(t, configured.IsInsecure())
				assert.Equal(t, types.KindAuthenticator, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
			},
		},
		"malformed step configuration": {
			config:  config.MechanismConfig{"user_id": "foo", "password": "bar"},
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"user_id": "baz", "password": 1}},
			assert: func(t *testing.T, err error, _, _ *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"enabling of error signaling is not allowed": {
			config: config.MechanismConfig{
				"user_id":         "foo",
				"password":        "bar",
				"error_signaling": map[string]any{"enabled": true},
			},
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"error_signaling": map[string]any{"enabled": false}}},
			assert: func(t *testing.T, err error, _, _ *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "'error_signaling'.'enabled' is not allowed")
			},
		},
		"reconfiguration of realm is possible": {
			config: config.MechanismConfig{
				"user_id":         "foo",
				"password":        "bar",
				"error_signaling": map[string]any{"enabled": false, "realm": "example"},
			},
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"error_signaling": map[string]any{"realm": "foo"}}},
			assert: func(t *testing.T, err error, prototype, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.Equal(t, prototype.userID, configured.userID)
				assert.Equal(t, prototype.password, configured.password)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.app, configured.app)
				assert.Equal(t, prototype.emptyAttributes, configured.emptyAttributes)
				assert.NotEqual(t, prototype.realm, configured.realm)
				assert.Equal(t, "foo", configured.realm)
				assert.False(t, configured.errorSignalingEnabled)
				assert.Equal(t, prototype.PrincipalName(), configured.PrincipalName())
				assert.Equal(t, "default", configured.PrincipalName())
				assert.False(t, configured.IsInsecure())
				assert.Equal(t, types.KindAuthenticator, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
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
		assert           func(t *testing.T, err error, sub pipeline.Subject)
	}{
		"no required header present": {
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("Authorization").Return("")

				ctx.EXPECT().Request().Return(&pipeline.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub pipeline.Subject) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrAuthentication)
				require.ErrorIs(t, err, pipeline.ErrArgument)
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

				ctx.EXPECT().Request().Return(&pipeline.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub pipeline.Subject) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrAuthentication)
				require.NotErrorIs(t, err, pipeline.ErrArgument)
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

				ctx.EXPECT().Request().Return(&pipeline.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub pipeline.Subject) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrAuthentication)
				require.NotErrorIs(t, err, pipeline.ErrArgument)
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

				ctx.EXPECT().Request().Return(&pipeline.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub pipeline.Subject) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrAuthentication)
				require.NotErrorIs(t, err, pipeline.ErrArgument)
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

				ctx.EXPECT().Request().Return(&pipeline.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub pipeline.Subject) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrAuthentication)
				require.NotErrorIs(t, err, pipeline.ErrArgument)
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

				ctx.EXPECT().Request().Return(&pipeline.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub pipeline.Subject) {
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

				ctx.EXPECT().Request().Return(&pipeline.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub pipeline.Subject) {
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

			sub := make(pipeline.Subject)

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

func TestBasicAuthAuthenticatorDecorateErrorResponse(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		conf           map[string]any
		expectedHeader string
		expectedCode   int
	}{
		"uses configured realm if error signaling is enabled": {
			conf: map[string]any{
				"user_id":  "foo",
				"password": "bar",
				"error_signaling": map[string]any{
					"enabled": true,
					"realm":   "example",
				},
			},
			expectedHeader: `Basic realm="example"`,
			expectedCode:   http.StatusUnauthorized,
		},
		"uses default realm if error signaling is enabled, but the realm is empty": {
			conf: map[string]any{
				"user_id":  "foo",
				"password": "bar",
				"error_signaling": map[string]any{
					"enabled": true,
				},
			},
			expectedHeader: `Basic realm="Please authenticate"`,
			expectedCode:   http.StatusUnauthorized,
		},
		"response is not decorated if error signaling is disabled": {
			conf: map[string]any{
				"user_id":  "foo",
				"password": "bar",
				"error_signaling": map[string]any{
					"enabled": false,
					"realm":   "example",
				},
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			auth, err := newBasicAuthAuthenticator(
				appCtx, "test", tc.conf)
			require.NoError(t, err)

			response := pipeline.ErrorResponse{
				Headers: map[string][]string{"X-Test": {"preserved"}},
			}

			auth.(*basicAuthAuthenticator).DecorateErrorResponse(pipeline.ErrAuthentication, &response)

			assert.Equal(t, tc.expectedCode, response.Code)

			if len(tc.expectedHeader) != 0 {
				require.Len(t, response.Headers, 2)
				assert.Equal(t, []string{tc.expectedHeader}, response.Headers[wwwAuthenticateHeader])
			} else {
				require.Len(t, response.Headers, 1)
			}

			assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
		})
	}
}
