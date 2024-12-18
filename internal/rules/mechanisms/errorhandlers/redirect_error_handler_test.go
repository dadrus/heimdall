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

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/validation"
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
			uc:     "configuration without required 'to' parameter",
			config: []byte(`code: 302`),
			assert: func(t *testing.T, err error, _ *redirectErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'to' is a required field")
			},
		},
		{
			uc: "with unexpected fields in configuration",
			config: []byte(`
to: http://foo.bar
if: true == false
`),
			assert: func(t *testing.T, err error, _ *redirectErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		{
			uc:     "with minimal valid configuration",
			config: []byte(`to: http://foo.bar`),
			assert: func(t *testing.T, err error, redEH *redirectErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, redEH)
				assert.Equal(t, "with minimal valid configuration", redEH.ID())

				toURL, err := redEH.to.Render(nil)
				require.NoError(t, err)

				assert.Equal(t, "http://foo.bar", toURL)
				assert.Equal(t, http.StatusFound, redEH.code)
			},
		},
		{
			uc: "with full valid configuration",
			config: []byte(`
to: http://foo.bar?origin={{ .Request.URL | urlenc }}
code: 301
`),
			assert: func(t *testing.T, err error, redEH *redirectErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, redEH)
				assert.Equal(t, "with full valid configuration", redEH.ID())

				ctx := mocks.NewContextMock(t)
				ctx.EXPECT().Request().
					Return(&heimdall.Request{
						URL: &heimdall.URL{URL: url.URL{Scheme: "http", Host: "foobar.baz", Path: "zab"}},
					})

				toURL, err := redEH.to.Render(map[string]any{
					"Request": ctx.Request(),
				})
				require.NoError(t, err)

				assert.Equal(t, "http://foo.bar?origin=http%3A%2F%2Ffoobar.baz%2Fzab", toURL)
				assert.Equal(t, http.StatusMovedPermanently, redEH.code)
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

			// WHEN
			errorHandler, err := newRedirectErrorHandler(appCtx, tc.uc, conf)

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
			uc:              "no new configuration provided",
			prototypeConfig: []byte(`to: http://foo.bar`),
			assert: func(t *testing.T, err error, prototype *redirectErrorHandler, configured *redirectErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc:              "empty configuration provided",
			prototypeConfig: []byte(`to: http://foo.bar`),
			config:          []byte(``),
			assert: func(t *testing.T, err error, prototype *redirectErrorHandler, configured *redirectErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc:              "unsupported configuration provided",
			prototypeConfig: []byte(`to: http://foo.bar`),
			config:          []byte(`to: http://foo.bar`),
			assert: func(t *testing.T, err error, _ *redirectErrorHandler, _ *redirectErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "reconfiguration of a redirect error handler is not supported")
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

			prototype, err := newRedirectErrorHandler(appCtx, tc.uc, pc)
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
		assert           func(t *testing.T, err error)
	}{
		{
			uc:     "with template rendering error",
			config: []byte(`to: http://foo.bar={{ len .foobar }}`),
			error:  heimdall.ErrAuthentication,
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to render")
			},
		},
		{
			uc:     "without return to url templating",
			config: []byte(`to: http://foo.bar`),
			error:  heimdall.ErrAuthentication,
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
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "with template and code set",
			config: []byte(`
to: http://foo.bar?origin={{ .Request.URL | urlenc }}
code: 300
`),
			error: heimdall.ErrAuthentication,
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				requestURL, err := url.Parse("http://test.org")
				require.NoError(t, err)

				ctx.EXPECT().Request().Return(&heimdall.Request{URL: &heimdall.URL{URL: *requestURL}})
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

			mctx := mocks.NewContextMock(t)
			mctx.EXPECT().AppContext().Return(context.Background())

			tc.configureContext(t, mctx)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)

			errorHandler, err := newRedirectErrorHandler(appCtx, "foo", conf)
			require.NoError(t, err)

			// WHEN
			execErr := errorHandler.Execute(mctx, tc.error)

			// THEN
			tc.assert(t, execErr)
		})
	}
}
