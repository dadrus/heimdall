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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
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
			uc:     "configuration without required 'if' parameter",
			config: []byte(`realm: FooBar`),
			assert: func(t *testing.T, err error, _ *wwwAuthenticateErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'if' is a required field")
			},
		},
		{
			uc: "without provided configuration",
			assert: func(t *testing.T, err error, _ *wwwAuthenticateErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'if' is a required field")
			},
		},
		{
			uc:     "with empty 'if' configuration",
			config: []byte(`if: ""`),
			assert: func(t *testing.T, err error, _ *wwwAuthenticateErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'if' is a required field")
			},
		},
		{
			uc:     "with invalid 'if' configuration",
			config: []byte(`if: foo`),
			assert: func(t *testing.T, err error, _ *wwwAuthenticateErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to compile")
			},
		},
		{
			uc: "with configuration containing unsupported fields",
			config: []byte(`
realm: FooBar
if: type(Error) == authentication_error
foo: bar
`),
			assert: func(t *testing.T, err error, _ *wwwAuthenticateErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		{
			uc:     "with minimum required configuration",
			config: []byte(`if: type(Error) == authentication_error`),
			assert: func(t *testing.T, err error, errorHandler *wwwAuthenticateErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, errorHandler)
				assert.Equal(t, "with minimum required configuration", errorHandler.ID())
				assert.Equal(t, "Please authenticate", errorHandler.realm)
				require.NotNil(t, errorHandler.c)
			},
		},
		{
			uc: "with all possible attributes",
			config: []byte(`
realm: "What is your password"
if: type(Error) == precondition_error
`),
			assert: func(t *testing.T, err error, errorHandler *wwwAuthenticateErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, errorHandler)
				assert.Equal(t, "with all possible attributes", errorHandler.ID())
				assert.Equal(t, "What is your password", errorHandler.realm)
				require.NotNil(t, errorHandler.c)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			errorHandler, err := newWWWAuthenticateErrorHandler(tc.uc, conf)

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
			prototypeConfig: []byte(`if: type(Error) == authentication_error`),
			assert: func(t *testing.T, err error, prototype *wwwAuthenticateErrorHandler,
				configured *wwwAuthenticateErrorHandler,
			) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "no new configuration provided", configured.ID())
			},
		},
		{
			uc:              "empty configuration provided",
			prototypeConfig: []byte(`if: type(Error) == authentication_error`),
			config:          []byte(``),
			assert: func(t *testing.T, err error, prototype *wwwAuthenticateErrorHandler,
				configured *wwwAuthenticateErrorHandler,
			) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "empty configuration provided", configured.ID())
			},
		},
		{
			uc:              "unsupported fields provided",
			prototypeConfig: []byte(`if: type(Error) == authentication_error`),
			config:          []byte(`to: http://foo.bar`),
			assert: func(t *testing.T, err error, _ *wwwAuthenticateErrorHandler,
				_ *wwwAuthenticateErrorHandler,
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		{
			uc:              "with 'if' reconfigured",
			prototypeConfig: []byte(`if: type(Error) in [authentication_error, authorization_error]`),
			config:          []byte(`if: type(Error) == precondition_error`),
			assert: func(t *testing.T, err error, prototype *wwwAuthenticateErrorHandler,
				configured *wwwAuthenticateErrorHandler,
			) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.NotNil(t, configured)
				assert.Equal(t, "with 'if' reconfigured", configured.ID())
				assert.Equal(t, "Please authenticate", prototype.realm)
				assert.Equal(t, prototype.realm, configured.realm)
				assert.NotEqual(t, prototype.c, configured.c)
			},
		},
		{
			uc:              "with invalid 'if' reconfigured",
			prototypeConfig: []byte(`if: type(Error) in [authentication_error, authorization_error]`),
			config:          []byte(`if: foo`),
			assert: func(t *testing.T, err error, _ *wwwAuthenticateErrorHandler,
				_ *wwwAuthenticateErrorHandler,
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to compile")
			},
		},
		{
			uc:              "with 'realm' reconfigured",
			prototypeConfig: []byte(`if: type(Error) == authentication_error`),
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
				assert.Equal(t, prototype.c, configured.c)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newWWWAuthenticateErrorHandler(tc.uc, pc)
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
		configureContext func(t *testing.T, ctx *mocks.ContextMock)
		assert           func(t *testing.T, wasResponsible bool, err error)
	}{
		{
			uc:     "not responsible for error",
			config: []byte(`if: type(Error) == authentication_error`),
			error:  heimdall.ErrInternal,
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, wasResponsible bool, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, wasResponsible)
			},
		},
		{
			uc:     "responsible for error with default realm",
			config: []byte(`if: type(Error) == authentication_error`),
			error:  heimdall.ErrAuthentication,
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
				ctx.EXPECT().SetPipelineError(heimdall.ErrAuthentication)
				ctx.EXPECT().AddHeaderForUpstream("WWW-Authenticate",
					mock.MatchedBy(func(val string) bool {
						assert.True(t, strings.HasPrefix(val, "Basic "))
						realm := strings.TrimLeft(val, "Basic ")
						assert.Equal(t, "realm=Please authenticate", realm)

						return true
					}))
			},
			assert: func(t *testing.T, wasResponsible bool, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, wasResponsible)
			},
		},
		{
			uc: "responsible for error with custom realm",
			config: []byte(`
realm: "Your password please"
if: type(Error) == authentication_error
`),
			error: heimdall.ErrAuthentication,
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
				ctx.EXPECT().SetPipelineError(heimdall.ErrAuthentication)
				ctx.EXPECT().AddHeaderForUpstream("WWW-Authenticate",
					mock.MatchedBy(func(val string) bool {
						assert.True(t, strings.HasPrefix(val, "Basic "))
						realm := strings.TrimLeft(val, "Basic ")
						assert.Equal(t, "realm=Your password please", realm)

						return true
					}))
			},
			assert: func(t *testing.T, wasResponsible bool, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, wasResponsible)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			mctx := mocks.NewContextMock(t)
			mctx.EXPECT().AppContext().Return(context.Background())

			tc.configureContext(t, mctx)

			errorHandler, err := newWWWAuthenticateErrorHandler("foo", conf)
			require.NoError(t, err)

			var (
				isResponsible bool
				execErr       error
			)

			// WHEN
			isResponsible = errorHandler.CanExecute(mctx, tc.error)
			if isResponsible {
				execErr = errorHandler.Execute(mctx, tc.error)
			}

			// THEN
			tc.assert(t, isResponsible, execErr)
		})
	}
}
