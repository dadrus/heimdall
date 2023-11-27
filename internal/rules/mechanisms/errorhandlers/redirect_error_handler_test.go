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
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCreateRedirectErrorHandler(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, redEH *redirectErrorHandler)
	}{
		{
			uc:     "configuration without required 'To' parameter",
			config: []byte(`code: 302`),
			assert: func(t *testing.T, err error, redEH *redirectErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'to' is a required field")
			},
		},
		{
			uc:     "configuration without required 'if' parameter",
			config: []byte(`to: http://foo.bar`),
			assert: func(t *testing.T, err error, redEH *redirectErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'if' is a required field")
			},
		},
		{
			uc: "with empty 'if' configuration",
			config: []byte(`
to: http://foo.bar
if: ""
`),
			assert: func(t *testing.T, err error, redEH *redirectErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'if' is a required field")
			},
		},
		{
			uc: "with invalid when conditions configuration",
			config: []byte(`
to: http://foo.bar
when: foo
`),
			assert: func(t *testing.T, err error, redEH *redirectErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		{
			uc: "with unexpected fields in configuration",
			config: []byte(`
to: http://foo.bar
bar: foo
if: true == false
`),
			assert: func(t *testing.T, err error, redEH *redirectErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		{
			uc: "with minimal valid configuration",
			config: []byte(`
to: http://foo.bar
if: Error.Source == "foo"
`),
			assert: func(t *testing.T, err error, redEH *redirectErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, redEH)
				assert.Equal(t, "with minimal valid configuration", redEH.ID())

				toURL, err := redEH.to.Render(nil)
				require.NoError(t, err)

				assert.Equal(t, "http://foo.bar", toURL)
				assert.Equal(t, http.StatusFound, redEH.code)
				assert.NotNil(t, redEH.c)
			},
		},
		{
			uc: "with full valid configuration",
			config: []byte(`
to: http://foo.bar?origin={{ .Request.URL | urlenc }}
code: 301
if: type(Error) == authentication_error
`),
			assert: func(t *testing.T, err error, redEH *redirectErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, redEH)
				assert.Equal(t, "with full valid configuration", redEH.ID())

				ctx := mocks.NewContextMock(t)
				ctx.EXPECT().Request().
					Return(&heimdall.Request{URL: &url.URL{Scheme: "http", Host: "foobar.baz", Path: "zab"}})

				toURL, err := redEH.to.Render(map[string]any{
					"Request": ctx.Request(),
				})
				require.NoError(t, err)

				assert.Equal(t, "http://foo.bar?origin=http%3A%2F%2Ffoobar.baz%2Fzab", toURL)
				assert.Equal(t, http.StatusMovedPermanently, redEH.code)
				assert.NotNil(t, redEH.c)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			errorHandler, err := newRedirectErrorHandler(tc.uc, conf)

			// THEN
			tc.assert(t, err, errorHandler)
		})
	}
}

func TestCreateRedirectErrorHandlerFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *redirectErrorHandler, configured *redirectErrorHandler)
	}{
		{
			uc: "no new configuration provided",
			prototypeConfig: []byte(`
to: http://foo.bar
if: type(Error) == authentication_error
`),
			assert: func(t *testing.T, err error, prototype *redirectErrorHandler, configured *redirectErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "no new configuration provided", configured.ID())
			},
		},
		{
			uc: "empty configuration provided",
			prototypeConfig: []byte(`
to: http://foo.bar
if: type(Error) == authentication_error
`),
			config: []byte(``),
			assert: func(t *testing.T, err error, prototype *redirectErrorHandler, configured *redirectErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "empty configuration provided", configured.ID())
			},
		},
		{
			uc: "unsupported fields provided",
			prototypeConfig: []byte(`
to: http://foo.bar
if: type(Error) == authentication_error
`),
			config: []byte(`to: http://foo.bar`),
			assert: func(t *testing.T, err error, prototype *redirectErrorHandler, configured *redirectErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		{
			uc: "required 'if' field provided",
			prototypeConfig: []byte(`
to: http://foo.bar
code: 301
if: type(Error) in [authentication_error, authorization_error] 
`),
			config: []byte(`if: type(Error) == precondition_error`),
			assert: func(t *testing.T, err error, prototype *redirectErrorHandler, configured *redirectErrorHandler) {
				t.Helper()

				ctx := mocks.NewContextMock(t)
				ctx.EXPECT().AppContext().Return(context.TODO())
				ctx.EXPECT().Request().Return(nil)

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.NotNil(t, configured)
				assert.Equal(t, "required 'if' field provided", configured.ID())
				assert.Equal(t, prototype.to, configured.to)
				assert.Equal(t, prototype.code, configured.code)
				assert.NotEqual(t, prototype.c, configured.c)
				assert.True(t, configured.CanExecute(ctx, heimdall.ErrArgument))
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newRedirectErrorHandler(tc.uc, pc)
			require.NoError(t, err)

			// WHEN
			errorHandler, err := prototype.WithConfig(conf)

			// THEN
			var (
				redirEH *redirectErrorHandler
				ok      bool
			)

			if err == nil {
				redirEH, ok = errorHandler.(*redirectErrorHandler)
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, redirEH)
		})
	}
}

func TestRedirectErrorHandlerExecute(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc               string
		config           []byte
		error            error
		configureContext func(t *testing.T, ctx *mocks.ContextMock)
		assert           func(t *testing.T, wasResponsible bool, err error)
	}{
		{
			uc: "not responsible for error",
			config: []byte(`
to: http://foo.bar
if: type(Error) == authentication_error
`),
			error: heimdall.ErrInternal,
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
			uc: "responsible for error but with template rendering error",
			config: []byte(`
to: http://foo.bar={{ len .foobar }}
if: type(Error) == authentication_error
`),
			error: heimdall.ErrAuthentication,
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, wasResponsible bool, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to render")
				assert.True(t, wasResponsible)
			},
		},
		{
			uc: "responsible without return to url templating",
			config: []byte(`
to: http://foo.bar
if: type(Error) == authentication_error
`),
			error: heimdall.ErrAuthentication,
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
				ctx.EXPECT().SetPipelineError(mock.MatchedBy(func(redirErr *heimdall.RedirectError) bool {
					t.Helper()

					assert.Equal(t, "http://foo.bar", redirErr.RedirectTo)
					assert.Equal(t, http.StatusFound, redirErr.Code)
					assert.Equal(t, "redirect", redirErr.Message)

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
			uc: "responsible with template and code set",
			config: []byte(`
to: http://foo.bar?origin={{ .Request.URL | urlenc }}
code: 300
if: type(Error) == authentication_error
`),
			error: heimdall.ErrAuthentication,
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				requestURL, err := url.Parse("http://test.org")
				require.NoError(t, err)

				ctx.EXPECT().Request().Return(&heimdall.Request{URL: requestURL})
				ctx.EXPECT().SetPipelineError(mock.MatchedBy(func(redirErr *heimdall.RedirectError) bool {
					t.Helper()

					redirectURL, err := url.Parse(redirErr.RedirectTo)
					require.NoError(t, err)

					assert.Equal(t, "http", redirectURL.Scheme)
					assert.Equal(t, "foo.bar", redirectURL.Host)
					assert.Len(t, redirectURL.Query(), 1)
					assert.Equal(t, "http://test.org", redirectURL.Query().Get("origin"))
					assert.Equal(t, http.StatusMultipleChoices, redirErr.Code)
					assert.Equal(t, "redirect", redirErr.Message)

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

			errorHandler, err := newRedirectErrorHandler("foo", conf)
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
