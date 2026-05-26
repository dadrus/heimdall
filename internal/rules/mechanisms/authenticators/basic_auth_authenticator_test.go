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
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/pipeline/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/validation"
)

func TestNewBasicAuthAuthenticator(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config config.MechanismConfig
		setup  func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.CredentialsHandleMock)
		assert func(t *testing.T, err error, auth *basicAuthAuthenticator)
	}{
		"valid configuration without error signaling": {
			config: config.MechanismConfig{
				"credentials": map[string]any{"source": "foo", "selector": "bar"},
			},
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, chm *secretsmocks.CredentialsHandleMock) {
				t.Helper()

				sr.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets.ResolveOption"),
					).
					Return(chm, nil)

				chm.EXPECT().
					Get(mock.Anything).
					Return(secrettypes.NewCredentials("bar", map[string]any{
						"user_id":  "bar",
						"password": "baz",
					}), true)
			},
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)

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
				require.NotNil(t, auth.informer)

				_, ok := auth.informer.Get(t.Context())
				assert.True(t, ok)
			},
		},
		"valid configuration with error signaling and default realm": {
			config: config.MechanismConfig{
				"credentials":     map[string]any{"source": "foo", "selector": "bar"},
				"error_signaling": map[string]any{"enabled": true},
			},
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.CredentialsHandleMock) {
				t.Helper()

				sr.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets.ResolveOption"),
					).
					Return(handle, nil)

				handle.EXPECT().
					Get(mock.Anything).
					Return(secrettypes.NewCredentials("bar", map[string]any{
						"user_id":  "bar",
						"password": "baz",
					}), true)
			},
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)

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
				require.NotNil(t, auth.informer)

				_, ok := auth.informer.Get(t.Context())
				assert.True(t, ok)
			},
		},
		"valid configuration with error signaling and custom realm": {
			config: config.MechanismConfig{
				"credentials":     map[string]any{"source": "foo", "selector": "bar"},
				"error_signaling": map[string]any{"enabled": true, "realm": "custom"},
			},
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.CredentialsHandleMock) {
				t.Helper()

				sr.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets.ResolveOption"),
					).
					Return(handle, nil)

				handle.EXPECT().
					Get(mock.Anything).
					Return(secrettypes.NewCredentials("bar", map[string]any{
						"user_id":  "bar",
						"password": "baz",
					}), true)
			},
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)

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
				require.NotNil(t, auth.informer)

				_, ok := auth.informer.Get(t.Context())
				assert.True(t, ok)
			},
		},
		"malformed credentials configuration": {
			config: config.MechanismConfig{
				"credentials": map[string]any{"selector": "bar"},
			},
			setup: func(t *testing.T, _ *secretsmocks.ResolverMock, _ *secretsmocks.CredentialsHandleMock) {
				t.Helper()
			},
			assert: func(t *testing.T, err error, _ *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding config")
			},
		},
		"credentials informer creation fails": {
			config: config.MechanismConfig{
				"credentials": map[string]any{"source": "foo", "selector": "bar"},
			},
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, _ *secretsmocks.CredentialsHandleMock) {
				t.Helper()

				sr.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets.ResolveOption"),
					).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, _ *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed creating credentials informer")
				require.ErrorIs(t, err, assert.AnError)
			},
		},
		"with unexpected config attribute": {
			config: config.MechanismConfig{
				"credentials": map[string]any{"source": "foo", "selector": "bar"},
				"foo":         "bar",
			},
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.CredentialsHandleMock) {
				t.Helper()

				sr.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets.ResolveOption"),
					).
					Return(handle, nil)
			},
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, auth)
				assert.NotNil(t, auth.informer)
			},
		},
		"without credentials configuration": {
			config: config.MechanismConfig{},
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.CredentialsHandleMock) {
				t.Helper()
			},
			assert: func(t *testing.T, err error, _ *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "'credentials'.'source' is a required field")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			sr := secretsmocks.NewResolverMock(t)
			handle := secretsmocks.NewCredentialsHandleMock(t)

			tc.setup(t, sr, handle)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().DecoderFactory().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))
			appCtx.EXPECT().Logger().Return(log.Logger)
			appCtx.EXPECT().SecretResolver().Maybe().Return(sr)

			mech, err := newBasicAuthAuthenticator(appCtx, uc, tc.config)

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
		setup   func(
			t *testing.T,
			appResolver *secretsmocks.ResolverMock,
			appHandle *secretsmocks.CredentialsHandleMock,
			stepResolver *secretsmocks.ResolverMock,
			stepHandle *secretsmocks.CredentialsHandleMock,
		)
		assert func(t *testing.T, err error, prototype, configured *basicAuthAuthenticator)
	}{
		"no new configuration for the configured authenticator": {
			config: config.MechanismConfig{
				"credentials": map[string]any{"source": "foo", "selector": "bar"},
			},
			setup: func(
				t *testing.T,
				appResolver *secretsmocks.ResolverMock,
				appHandle *secretsmocks.CredentialsHandleMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.CredentialsHandleMock,
			) {
				t.Helper()

				appResolver.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets.ResolveOption"),
					).
					Return(appHandle, nil)
			},
			assert: func(t *testing.T, err error, prototype, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "no new configuration for the configured authenticator", configured.ID())
			},
		},
		"credentials differs": {
			config: config.MechanismConfig{
				"credentials": map[string]any{"source": "foo", "selector": "bar"},
			},
			stepDef: types.StepDefinition{Config: config.MechanismConfig{
				"credentials": map[string]any{"source": "foo", "selector": "baz"},
			}},
			setup: func(
				t *testing.T,
				appResolver *secretsmocks.ResolverMock,
				appHandle *secretsmocks.CredentialsHandleMock,
				stepResolver *secretsmocks.ResolverMock,
				stepHandle *secretsmocks.CredentialsHandleMock,
			) {
				t.Helper()

				appResolver.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets.ResolveOption"),
					).
					Return(appHandle, nil)

				stepResolver.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "baz"},
						mock.AnythingOfType("secrets.ResolveOption"),
					).
					Return(stepHandle, nil)
			},
			assert: func(t *testing.T, err error, prototype, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)

				assert.NotEqual(t, prototype.informer, configured.informer)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, "credentials differs", configured.ID())
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
		"fails creating informer for new credentials": {
			config: config.MechanismConfig{
				"credentials": map[string]any{"source": "foo", "selector": "bar"},
			},
			stepDef: types.StepDefinition{Config: config.MechanismConfig{
				"credentials": map[string]any{"source": "foo", "selector": "baz"},
			}},
			setup: func(
				t *testing.T,
				appResolver *secretsmocks.ResolverMock,
				appHandle *secretsmocks.CredentialsHandleMock,
				stepResolver *secretsmocks.ResolverMock,
				_ *secretsmocks.CredentialsHandleMock,
			) {
				t.Helper()

				appResolver.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets.ResolveOption"),
					).
					Return(appHandle, nil)

				stepResolver.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "baz"},
						mock.AnythingOfType("secrets.ResolveOption"),
					).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, _, _ *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed creating credentials informer")
				require.ErrorIs(t, err, assert.AnError)
			},
		},
		"malformed step configuration": {
			config: config.MechanismConfig{
				"credentials": map[string]any{"source": "foo", "selector": "bar"},
			},
			stepDef: types.StepDefinition{Config: config.MechanismConfig{
				"credentials": map[string]any{"selector": "baz"},
			}},
			setup: func(
				t *testing.T,
				appResolver *secretsmocks.ResolverMock,
				appHandle *secretsmocks.CredentialsHandleMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.CredentialsHandleMock,
			) {
				t.Helper()

				appResolver.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets.ResolveOption"),
					).
					Return(appHandle, nil)
			},
			assert: func(t *testing.T, err error, _, _ *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"only step id configured": {
			config: config.MechanismConfig{
				"credentials": map[string]any{"source": "foo", "selector": "bar"},
			},
			stepDef: types.StepDefinition{ID: "foo"},
			setup: func(
				t *testing.T,
				appResolver *secretsmocks.ResolverMock,
				appHandle *secretsmocks.CredentialsHandleMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.CredentialsHandleMock,
			) {
				t.Helper()

				appResolver.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets.ResolveOption"),
					).
					Return(appHandle, nil)
			},
			assert: func(t *testing.T, err error, prototype, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.NotEqual(t, prototype.ID(), configured.ID())
				assert.Equal(t, "foo", configured.ID())
				assert.Equal(t, prototype.informer, configured.informer)
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
				"credentials":     map[string]any{"source": "foo", "selector": "bar"},
				"error_signaling": map[string]any{"enabled": true},
			},
			stepDef: types.StepDefinition{Principal: "foo"},
			setup: func(
				t *testing.T,
				appResolver *secretsmocks.ResolverMock,
				appHandle *secretsmocks.CredentialsHandleMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.CredentialsHandleMock,
			) {
				t.Helper()

				appResolver.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets.ResolveOption"),
					).
					Return(appHandle, nil)
			},
			assert: func(t *testing.T, err error, prototype, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.Equal(t, prototype.informer, configured.informer)
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
		"reconfiguration of error signaling is possible": {
			config: config.MechanismConfig{
				"credentials":     map[string]any{"source": "foo", "selector": "bar"},
				"error_signaling": map[string]any{"enabled": false},
			},
			stepDef: types.StepDefinition{
				Config: config.MechanismConfig{
					"error_signaling": map[string]any{
						"enabled": true,
						"realm":   "example",
					},
				},
			},
			setup: func(
				t *testing.T,
				appResolver *secretsmocks.ResolverMock,
				appHandle *secretsmocks.CredentialsHandleMock,
				_ *secretsmocks.ResolverMock,
				_ *secretsmocks.CredentialsHandleMock,
			) {
				t.Helper()

				appResolver.EXPECT().
					Credentials(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets.ResolveOption"),
					).
					Return(appHandle, nil)
			},
			assert: func(t *testing.T, err error, prototype, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.Equal(t, prototype.informer, configured.informer)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.app, configured.app)
				assert.Equal(t, prototype.emptyAttributes, configured.emptyAttributes)
				assert.NotEqual(t, prototype.realm, configured.realm)
				assert.Equal(t, "example", configured.realm)
				assert.True(t, configured.errorSignalingEnabled)
				assert.Equal(t, prototype.PrincipalName(), configured.PrincipalName())
				assert.Equal(t, "default", configured.PrincipalName())
				assert.False(t, configured.IsInsecure())
				assert.Equal(t, types.KindAuthenticator, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appResolver := secretsmocks.NewResolverMock(t)
			appHandle := secretsmocks.NewCredentialsHandleMock(t)
			stepResolver := secretsmocks.NewResolverMock(t)
			stepHandle := secretsmocks.NewCredentialsHandleMock(t)

			tc.setup(t, appResolver, appHandle, stepResolver, stepHandle)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().DecoderFactory().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))
			appCtx.EXPECT().Logger().Return(log.Logger)
			appCtx.EXPECT().SecretResolver().Return(appResolver)

			mech, err := newBasicAuthAuthenticator(appCtx, uc, tc.config)
			require.NoError(t, err)

			configured, ok := mech.(*basicAuthAuthenticator)
			require.True(t, ok)

			step, err := mech.CreateStep(t.Context(), stepResolver, tc.stepDef)

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

	conf := config.MechanismConfig{
		"credentials": map[string]any{"source": "foo", "selector": "bar"},
	}

	for uc, tc := range map[string]struct {
		stepDef          types.StepDefinition
		handleValue      secrets.Credentials
		handleOK         bool
		configureContext func(t *testing.T, ctx *mocks.ContextMock)
		assert           func(t *testing.T, err error, sub pipeline.Subject)
	}{
		"no required header present": {
			handleValue: secrettypes.NewCredentials("bar", map[string]any{
				"user_id":  "bar",
				"password": "baz",
			}),
			handleOK: true,
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
			handleValue: secrettypes.NewCredentials("bar", map[string]any{
				"user_id":  "bar",
				"password": "baz",
			}),
			handleOK: true,
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
			handleValue: secrettypes.NewCredentials("bar", map[string]any{
				"user_id":  "bar",
				"password": "baz",
			}),
			handleOK: true,
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
		"no credentials available": {
			handleOK: false,
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("Authorization").
					Return("Basic " + base64.StdEncoding.EncodeToString([]byte("bar:baz")))

				ctx.EXPECT().Request().Return(&pipeline.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub pipeline.Subject) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "basic auth credentials are not available")

				assert.Empty(t, sub)
			},
		},
		"invalid credentials payload": {
			handleValue: secrettypes.NewCredentials("bar", map[string]any{
				"foo": "bar",
			}),
			handleOK: true,
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("Authorization").
					Return("Basic " + base64.StdEncoding.EncodeToString([]byte("bar:baz")))

				ctx.EXPECT().Request().Return(&pipeline.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub pipeline.Subject) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "basic auth credentials are not available")

				assert.Empty(t, sub)
			},
		},
		"invalid user id": {
			handleValue: secrettypes.NewCredentials("bar", map[string]any{
				"user_id":  "bar",
				"password": "baz",
			}),
			handleOK: true,
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
				require.ErrorContains(t, err, "invalid user credentials")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "invalid user id", identifier.ID())

				assert.Empty(t, sub)
			},
		},
		"invalid password": {
			handleValue: secrettypes.NewCredentials("bar", map[string]any{
				"user_id":  "bar",
				"password": "baz",
			}),
			handleOK: true,
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
			handleValue: secrettypes.NewCredentials("bar", map[string]any{
				"user_id":  "bar",
				"password": "baz",
			}),
			handleOK: true,
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("Authorization").
					Return("Basic " + base64.StdEncoding.EncodeToString([]byte("bar:baz")))

				ctx.EXPECT().Request().Return(&pipeline.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub pipeline.Subject) {
				t.Helper()

				require.NoError(t, err)

				require.Equal(t, "bar", sub.ID())
				assert.NotNil(t, sub.Attributes())
				assert.Empty(t, sub.Attributes())
			},
		},
		"custom principal is created for valid credentials": {
			stepDef: types.StepDefinition{Principal: "baz"},
			handleValue: secrettypes.NewCredentials("bar", map[string]any{
				"user_id":  "bar",
				"password": "baz",
			}),
			handleOK: true,
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("Authorization").
					Return("Basic " + base64.StdEncoding.EncodeToString([]byte("bar:baz")))

				ctx.EXPECT().Request().Return(&pipeline.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub pipeline.Subject) {
				t.Helper()

				require.NoError(t, err)

				assert.Empty(t, sub.ID())
				assert.Empty(t, sub.Attributes())
				assert.NotNil(t, sub["baz"])
				assert.Equal(t, "bar", sub["baz"].ID)
				assert.Empty(t, sub["baz"].Attributes)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			sr := secretsmocks.NewResolverMock(t)
			handle := secretsmocks.NewCredentialsHandleMock(t)

			sr.EXPECT().
				Credentials(
					mock.Anything,
					secrets.Reference{Source: "foo", Selector: "bar"},
					mock.AnythingOfType("secrets.ResolveOption"),
				).
				Return(handle, nil)

			handle.EXPECT().
				Get(mock.Anything).
				Maybe().
				Return(tc.handleValue, tc.handleOK)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().DecoderFactory().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))
			appCtx.EXPECT().Logger().Return(log.Logger)
			appCtx.EXPECT().SecretResolver().Return(sr)

			mech, err := newBasicAuthAuthenticator(appCtx, uc, conf)
			require.NoError(t, err)

			step, err := mech.CreateStep(t.Context(), sr, tc.stepDef)
			require.NoError(t, err)

			ctx := mocks.NewContextMock(t)
			ctx.EXPECT().Context().Return(t.Context()).Maybe()
			tc.configureContext(t, ctx)

			sub := make(pipeline.Subject)

			err = step.Execute(ctx, sub)

			tc.assert(t, err, sub)
		})
	}
}

func TestBasicAuthAuthenticatorAccept(t *testing.T) {
	t.Parallel()

	auth := &basicAuthAuthenticator{}
	visitor := mocks.NewVisitorMock(t)

	visitor.EXPECT().VisitInsecure(auth)
	visitor.EXPECT().VisitPrincipalNamer(auth)

	auth.Accept(visitor)
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
				"credentials":     map[string]any{"source": "foo", "selector": "bar"},
				"error_signaling": map[string]any{"enabled": true, "realm": "example"},
			},
			expectedHeader: `Basic realm="example"`,
			expectedCode:   http.StatusUnauthorized,
		},
		"uses default realm if error signaling is enabled, but the realm is empty": {
			conf: map[string]any{
				"credentials":     map[string]any{"source": "foo", "selector": "bar"},
				"error_signaling": map[string]any{"enabled": true},
			},
			expectedHeader: `Basic realm="Please authenticate"`,
			expectedCode:   http.StatusUnauthorized,
		},
		"response is not decorated if error signaling is disabled": {
			conf: map[string]any{
				"credentials":     map[string]any{"source": "foo", "selector": "bar"},
				"error_signaling": map[string]any{"enabled": false, "realm": "example"},
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			sr := secretsmocks.NewResolverMock(t)
			handle := secretsmocks.NewCredentialsHandleMock(t)

			sr.EXPECT().
				Credentials(
					mock.Anything,
					secrets.Reference{Source: "foo", Selector: "bar"},
					mock.AnythingOfType("secrets.ResolveOption"),
				).
				Return(handle, nil)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().DecoderFactory().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))
			appCtx.EXPECT().Logger().Return(log.Logger)
			appCtx.EXPECT().SecretResolver().Return(sr)

			auth, err := newBasicAuthAuthenticator(appCtx, "test", tc.conf)
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
