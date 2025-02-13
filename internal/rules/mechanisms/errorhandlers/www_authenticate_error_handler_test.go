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
	"context"
	"strings"
	"testing"

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

func TestCreateWWWAuthenticateErrorHandler(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, errorHandler *wwwAuthenticateErrorHandler)
	}{
		{
			uc: "with configuration containing unsupported fields",
			config: []byte(`
realm: FooBar
if: type(Error) == authentication_error
`),
			assert: func(t *testing.T, err error, _ *wwwAuthenticateErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		{
			uc: "without configuration (minimal configuration)",
			assert: func(t *testing.T, err error, errorHandler *wwwAuthenticateErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, errorHandler)
				assert.Equal(t, "without configuration (minimal configuration)", errorHandler.ID())
				assert.Equal(t, "Please authenticate", errorHandler.realm)
			},
		},
		{
			uc:     "with all possible attributes",
			config: []byte(`realm: "What is your password"`),
			assert: func(t *testing.T, err error, errorHandler *wwwAuthenticateErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, errorHandler)
				assert.Equal(t, "with all possible attributes", errorHandler.ID())
				assert.Equal(t, "What is your password", errorHandler.realm)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			// WHEN
			errorHandler, err := newWWWAuthenticateErrorHandler(appCtx, tc.uc, conf)

			// THEN
			tc.assert(t, err, errorHandler)
		})
	}
}

func TestCreateWWWAuthenticateErrorHandlerFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *wwwAuthenticateErrorHandler,
			configured *wwwAuthenticateErrorHandler)
	}{
		{
			uc:              "no new configuration provided",
			prototypeConfig: []byte(`realm: "foo"`),
			assert: func(t *testing.T, err error, prototype *wwwAuthenticateErrorHandler,
				configured *wwwAuthenticateErrorHandler,
			) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc:              "empty configuration provided",
			prototypeConfig: []byte(`realm: "foo"`),
			config:          []byte(``),
			assert: func(t *testing.T, err error, prototype *wwwAuthenticateErrorHandler,
				configured *wwwAuthenticateErrorHandler,
			) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc:     "unsupported fields provided",
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
		{
			uc:              "with 'realm' reconfigured",
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
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
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

			prototype, err := newWWWAuthenticateErrorHandler(appCtx, tc.uc, pc)
			require.NoError(t, err)

			// WHEN
			errorHandler, err := prototype.WithConfig(conf)

			// THEN
			var (
				wwwAuthEH *wwwAuthenticateErrorHandler
				ok        bool
			)

			if err == nil {
				wwwAuthEH, ok = errorHandler.(*wwwAuthenticateErrorHandler)
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, wwwAuthEH)
		})
	}
}

func TestWWWAuthenticateErrorHandlerExecute(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc               string
		config           []byte
		error            error
		configureContext func(t *testing.T, ctx *mocks.RequestContextMock)
		assert           func(t *testing.T, err error)
	}{
		{
			uc:    "with default realm",
			error: heimdall.ErrAuthentication,
			configureContext: func(t *testing.T, ctx *mocks.RequestContextMock) {
				t.Helper()

				ctx.EXPECT().SetPipelineError(heimdall.ErrAuthentication)
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
		{
			uc:     "with custom realm",
			config: []byte(`realm: "Your password please"`),
			error:  heimdall.ErrAuthentication,
			configureContext: func(t *testing.T, ctx *mocks.RequestContextMock) {
				t.Helper()

				ctx.EXPECT().SetPipelineError(heimdall.ErrAuthentication)
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
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			mctx := mocks.NewRequestContextMock(t)
			mctx.EXPECT().Context().Return(context.Background())

			tc.configureContext(t, mctx)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			errorHandler, err := newWWWAuthenticateErrorHandler(appCtx, "foo", conf)
			require.NoError(t, err)

			// WHEN
			execErr := errorHandler.Execute(mctx, tc.error)

			// THEN
			tc.assert(t, execErr)
		})
	}
}
