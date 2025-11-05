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

package errorhandlers

import (
	"strings"
	"testing"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewWWWAuthenticateErrorHandler(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config []byte
		assert func(t *testing.T, err error, errorHandler *wwwAuthenticateErrorHandler)
	}{
		"with configuration containing unsupported fields": {
			config: []byte(`
realm: FooBar
if: type(Error) == authentication_error
`),
			assert: func(t *testing.T, err error, errorHandler *wwwAuthenticateErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, errorHandler)
			},
		},
		"without configuration (minimal configuration)": {
			assert: func(t *testing.T, err error, errorHandler *wwwAuthenticateErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, errorHandler)
				assert.Equal(t, "without configuration (minimal configuration)", errorHandler.ID())
				assert.Equal(t, errorHandler.Name(), errorHandler.ID())
				assert.Equal(t, "Please authenticate", errorHandler.realm)
			},
		},
		"with all possible attributes": {
			config: []byte(`realm: "What is your password"`),
			assert: func(t *testing.T, err error, errorHandler *wwwAuthenticateErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, errorHandler)
				assert.Equal(t, "with all possible attributes", errorHandler.ID())
				assert.Equal(t, errorHandler.Name(), errorHandler.ID())
				assert.Equal(t, "What is your password", errorHandler.realm)
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
			mech, err := newWWWAuthenticateErrorHandler(appCtx, uc, conf)

			// THEN
			eh, ok := mech.(*wwwAuthenticateErrorHandler)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, eh)
		})
	}
}

func TestWWWAuthenticateErrorHandlerCreateStep(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		prototypeConfig []byte
		config          []byte
		stepID          string
		assert          func(t *testing.T, err error, prototype *wwwAuthenticateErrorHandler,
			configured *wwwAuthenticateErrorHandler)
	}{
		"no new configuration and no step ID": {
			prototypeConfig: []byte(`realm: "foo"`),
			assert: func(t *testing.T, err error, prototype *wwwAuthenticateErrorHandler,
				configured *wwwAuthenticateErrorHandler,
			) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		"no new configuration but with step ID": {
			prototypeConfig: []byte(`realm: "foo"`),
			stepID:          "bar",
			assert: func(t *testing.T, err error, prototype *wwwAuthenticateErrorHandler,
				configured *wwwAuthenticateErrorHandler,
			) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, "bar", configured.ID())
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, prototype.realm, configured.realm)
				assert.Equal(t, prototype.app, configured.app)
			},
		},
		"unsupported fields provided": {
			config: []byte(`to: http://foo.bar`),
			assert: func(t *testing.T, err error, _ *wwwAuthenticateErrorHandler,
				_ *wwwAuthenticateErrorHandler,
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"with 'realm' reconfigured": {
			prototypeConfig: []byte(`realm: "Foobar"`),
			config:          []byte(`realm: "You password please"`),
			assert: func(t *testing.T, err error, prototype *wwwAuthenticateErrorHandler,
				configured *wwwAuthenticateErrorHandler,
			) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.NotNil(t, configured)
				assert.Equal(t, "with 'realm' reconfigured", configured.ID())
				assert.NotEqual(t, prototype.realm, configured.realm)
				assert.Equal(t, "You password please", configured.realm)
			},
		},
		"with empty 'realm' reconfigured": {
			prototypeConfig: []byte(`realm: "Foobar"`),
			config:          []byte(`realm: ""`),
			assert: func(t *testing.T, err error, _ *wwwAuthenticateErrorHandler,
				_ *wwwAuthenticateErrorHandler,
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'realm' is a required field")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			mech, err := newWWWAuthenticateErrorHandler(appCtx, uc, pc)
			require.NoError(t, err)

			configured, ok := mech.(*wwwAuthenticateErrorHandler)
			require.True(t, ok)

			// WHEN
			step, err := mech.CreateStep(types.StepDefinition{ID: tc.stepID, Config: conf})

			// THEN
			eh, ok := step.(*wwwAuthenticateErrorHandler)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, configured, eh)
		})
	}
}

func TestWWWAuthenticateErrorHandlerExecute(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config           []byte
		configureContext func(t *testing.T, ctx *mocks.ContextMock)
		assert           func(t *testing.T, err error)
	}{
		"with default realm": {
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().SetError(heimdall.ErrAuthentication)
				ctx.EXPECT().AddHeaderForUpstream("WWW-Authenticate",
					mock.MatchedBy(func(val string) bool {
						assert.True(t, strings.HasPrefix(val, "Basic "))
						realm := strings.TrimLeft(val, "Basic ")
						assert.Equal(t, "realm=Please authenticate", realm)

						return true
					}))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"with custom realm": {
			config: []byte(`realm: "Your password please"`),
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().SetError(heimdall.ErrAuthentication)
				ctx.EXPECT().AddHeaderForUpstream("WWW-Authenticate",
					mock.MatchedBy(func(val string) bool {
						assert.True(t, strings.HasPrefix(val, "Basic "))
						realm := strings.TrimLeft(val, "Basic ")
						assert.Equal(t, "realm=Your password please", realm)

						return true
					}))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			mctx := mocks.NewContextMock(t)
			mctx.EXPECT().Context().Return(t.Context())

			tc.configureContext(t, mctx)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			mech, err := newWWWAuthenticateErrorHandler(appCtx, "foo", conf)
			require.NoError(t, err)

			step, err := mech.CreateStep(types.StepDefinition{ID: ""})
			require.NoError(t, err)

			// WHEN
			err = step.Execute(mctx, nil)

			// THEN
			tc.assert(t, err)
		})
	}
}
