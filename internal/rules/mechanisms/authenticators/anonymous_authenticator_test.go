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

	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/identity"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewAnonymousAuthenticator(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config []byte
		assert func(t *testing.T, err error, auth *anonymousAuthenticator)
	}{
		"principal is set to anon": {
			config: []byte("principal: anon"),
			assert: func(t *testing.T, err error, auth *anonymousAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "anon", auth.principal.ID)
				assert.Equal(t, "principal is set to anon", auth.ID())
				assert.Equal(t, auth.Name(), auth.ID())
				assert.Empty(t, auth.principal.Attributes)
				assert.NotNil(t, auth.principal.Attributes)
			},
		},
		"default principal": {
			config: nil,
			assert: func(t *testing.T, err error, auth *anonymousAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "anonymous", auth.principal.ID)
				assert.Equal(t, "default principal", auth.ID())
				assert.Equal(t, auth.Name(), auth.ID())
				assert.Empty(t, auth.principal.Attributes)
				assert.NotNil(t, auth.principal.Attributes)
			},
		},
		"unsupported attributes": {
			config: []byte("foo: bar"),
			assert: func(t *testing.T, err error, auth *anonymousAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "anonymous", auth.principal.ID)
				assert.Equal(t, "unsupported attributes", auth.ID())
				assert.Equal(t, auth.Name(), auth.ID())
				assert.Empty(t, auth.principal.Attributes)
				assert.NotNil(t, auth.principal.Attributes)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			// WHEN
			mechanism, err := newAnonymousAuthenticator(appCtx, uc, conf)

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
		stepConfig []byte
		config     []byte
		stepID     string
		assert     func(t *testing.T, err error, prototype *anonymousAuthenticator, configured *anonymousAuthenticator)
	}{
		"no new configuration for the configured authenticator": {
			assert: func(t *testing.T, err error, prototype *anonymousAuthenticator, configured *anonymousAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
				assert.Equal(t, "no new configuration for the configured authenticator", configured.ID())
			},
		},
		"new principal for the configured authenticator": {
			stepConfig: []byte("principal: anon"),
			config:     []byte("principal: foo"),
			assert: func(t *testing.T, err error, prototype *anonymousAuthenticator, configured *anonymousAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Empty(t, prototype.principal.Attributes)
				assert.NotNil(t, prototype.principal.Attributes)
				assert.Equal(t, prototype.principal.Attributes, configured.principal.Attributes)
				assert.Equal(t, "new principal for the configured authenticator", configured.ID())
				assert.NotEqual(t, prototype.principal, configured.principal)
				assert.Equal(t, "anon", prototype.principal.ID)
				assert.Equal(t, "foo", configured.principal.ID)
			},
		},
		"step id is configured": {
			stepConfig: []byte("principal: anon"),
			stepID:     "foo",
			assert: func(t *testing.T, err error, prototype *anonymousAuthenticator, configured *anonymousAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, "step id is configured", prototype.ID())
				assert.Equal(t, "foo", configured.ID())
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, prototype.principal, configured.principal)
				assert.NotNil(t, prototype.principal.Attributes)
			},
		},
		"empty principal for the configured authenticator": {
			stepConfig: []byte("principal: anon"),
			config:     []byte("principal: ''"),
			assert: func(t *testing.T, err error, _ *anonymousAuthenticator, _ *anonymousAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"malformed configured authenticator config": {
			config: []byte("foo: bar"),
			assert: func(t *testing.T, err error, _ *anonymousAuthenticator, _ *anonymousAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			pc, err := testsupport.DecodeTestConfig(tc.stepConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			mechanism, err := newAnonymousAuthenticator(appCtx, uc, pc)
			require.NoError(t, err)

			// WHEN
			step, err := mechanism.CreateStep(types.StepDefinition{ID: tc.stepID, Config: conf})

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
	exp := &identity.Principal{ID: "anon"}
	auth := anonymousAuthenticator{principal: exp, id: "anon_auth"}

	ctx := mocks.NewContextMock(t)
	ctx.EXPECT().Context().Return(t.Context())

	sub := make(identity.Subject)

	// WHEN
	err := auth.Execute(ctx, sub)

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
