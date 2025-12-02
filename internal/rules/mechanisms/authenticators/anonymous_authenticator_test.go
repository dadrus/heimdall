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

func TestNewAnonymousAuthenticator(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config config.MechanismConfig
		assert func(t *testing.T, err error, auth *anonymousAuthenticator)
	}{
		"principal is set to anon": {
			config: config.MechanismConfig{"principal": "anon"},
			assert: func(t *testing.T, err error, auth *anonymousAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "anon", auth.principal.ID)
				assert.Equal(t, "principal is set to anon", auth.ID())
				assert.Equal(t, auth.Name(), auth.ID())
				assert.Empty(t, auth.principal.Attributes)
				assert.NotNil(t, auth.principal.Attributes)
				assert.Equal(t, "default", auth.principalName)
			},
		},
		"default principal": {
			assert: func(t *testing.T, err error, auth *anonymousAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "anonymous", auth.principal.ID)
				assert.Equal(t, "default principal", auth.ID())
				assert.Equal(t, auth.Name(), auth.ID())
				assert.Empty(t, auth.principal.Attributes)
				assert.NotNil(t, auth.principal.Attributes)
				assert.Equal(t, "default", auth.principalName)
			},
		},
		"unsupported attributes are ignored": {
			config: config.MechanismConfig{"foo": "bar"},
			assert: func(t *testing.T, err error, auth *anonymousAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "anonymous", auth.principal.ID)
				assert.Equal(t, "unsupported attributes are ignored", auth.ID())
				assert.Equal(t, auth.Name(), auth.ID())
				assert.Empty(t, auth.principal.Attributes)
				assert.NotNil(t, auth.principal.Attributes)
				assert.Equal(t, "default", auth.principalName)
			},
		},
		"malformed configuration": {
			config: config.MechanismConfig{"principal": 1},
			assert: func(t *testing.T, err error, _ *anonymousAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding config for anonymous authenticator")
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
			mechanism, err := newAnonymousAuthenticator(appCtx, uc, tc.config)

			// THEN
			auth, ok := mechanism.(*anonymousAuthenticator)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, auth)
		})
	}
}

func TestAnonymousAuthenticatorCreateStep(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config  config.MechanismConfig
		stepDef types.StepDefinition
		assert  func(t *testing.T, err error, prototype, configured *anonymousAuthenticator)
	}{
		"no new configuration for the configured authenticator": {
			assert: func(t *testing.T, err error, prototype, configured *anonymousAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
				assert.Equal(t, "no new configuration for the configured authenticator", configured.ID())
			},
		},
		"new principal definition for the configured authenticator": {
			config:  config.MechanismConfig{"principal": "anon"},
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"principal": "foo"}},
			assert: func(t *testing.T, err error, prototype, configured *anonymousAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Empty(t, prototype.principal.Attributes)
				assert.NotNil(t, prototype.principal.Attributes)
				assert.Equal(t, prototype.principal.Attributes, configured.principal.Attributes)
				assert.Equal(t, "new principal definition for the configured authenticator", configured.ID())
				assert.NotEqual(t, prototype.principal, configured.principal)
				assert.Equal(t, "anon", prototype.principal.ID)
				assert.Equal(t, "foo", configured.principal.ID)
				assert.Equal(t, prototype.principalName, configured.principalName)
			},
		},
		"only step id is configured": {
			config:  config.MechanismConfig{"principal": "anon"},
			stepDef: types.StepDefinition{ID: "foo"},
			assert: func(t *testing.T, err error, prototype, configured *anonymousAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, "only step id is configured", prototype.ID())
				assert.Equal(t, "foo", configured.ID())
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, prototype.principal, configured.principal)
				assert.NotNil(t, prototype.principal.Attributes)
				assert.Equal(t, prototype.principalName, configured.principalName)
			},
		},
		"only principal name is configured": {
			config:  config.MechanismConfig{"principal": "anon"},
			stepDef: types.StepDefinition{Principal: "foo"},
			assert: func(t *testing.T, err error, prototype, configured *anonymousAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, configured.ID(), prototype.ID())
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, prototype.principal, configured.principal)
				assert.NotNil(t, prototype.principal.Attributes)
				assert.NotEqual(t, prototype.principalName, configured.principalName)
				assert.Equal(t, "foo", configured.principalName)
			},
		},
		"empty principal for the configured authenticator": {
			config:  config.MechanismConfig{"principal": "anon"},
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"principal": ""}},
			assert: func(t *testing.T, err error, _, _ *anonymousAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"malformed configured authenticator config": {
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"foo": "bar"}},
			assert: func(t *testing.T, err error, _, _ *anonymousAuthenticator) {
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

			mechanism, err := newAnonymousAuthenticator(appCtx, uc, tc.config)
			require.NoError(t, err)

			// WHEN
			step, err := mechanism.CreateStep(tc.stepDef)

			// THEN
			configured, ok := step.(*anonymousAuthenticator)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, mechanism.(*anonymousAuthenticator), configured)
		})
	}
}

func TestAnonymousAuthenticatorExecute(t *testing.T) {
	t.Parallel()

	// GIVEN
	es := config.EnforcementSettings{}
	validator, err := validation.NewValidator(
		validation.WithTagValidator(es),
		validation.WithErrorTranslator(es),
	)
	require.NoError(t, err)

	appCtx := app.NewContextMock(t)
	appCtx.EXPECT().Validator().Return(validator)
	appCtx.EXPECT().Logger().Return(log.Logger)

	mech, err := newAnonymousAuthenticator(appCtx, "anon_auth", map[string]any{"principal": "anon"})
	require.NoError(t, err)

	auth := mech.(*anonymousAuthenticator)

	ctx := mocks.NewContextMock(t)
	ctx.EXPECT().Context().Return(t.Context())

	sub := make(identity.Subject)
	exp := &identity.Principal{ID: "anon", Attributes: make(map[string]any)}

	// WHEN
	err = auth.Execute(ctx, sub)

	// THEN
	require.NoError(t, err)
	assert.Equal(t, exp, sub["default"])
}

func TestAnonymousAuthenticatorIsInsecure(t *testing.T) {
	t.Parallel()

	// GIVEN
	auth := anonymousAuthenticator{}

	// WHEN & THEN
	require.True(t, auth.IsInsecure())
}

func TestAnonymousAuthenticatorKind(t *testing.T) {
	t.Parallel()

	// GIVEN
	auth := anonymousAuthenticator{}

	// WHEN & THEN
	require.Equal(t, types.KindAuthenticator, auth.Kind())
}
