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
	"net/http"
	"net/url"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCreateRedirectErrorHandler(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		enforceTLS bool
		config     []byte
		assert     func(t *testing.T, err error, redEH *redirectErrorHandler)
	}{
		"configuration without required 'to' parameter": {
			config: []byte(`code: 302`),
			assert: func(t *testing.T, err error, _ *redirectErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'to' is a required field")
			},
		},
		"with unexpected fields in configuration": {
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
		"with minimal valid configuration, enforced and used TLS": {
			enforceTLS: true,
			config:     []byte(`to: https://foo.bar`),
			assert: func(t *testing.T, err error, redEH *redirectErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, redEH)
				assert.Equal(t, "with minimal valid configuration, enforced and used TLS", redEH.ID())

				toURL, err := redEH.to.Render(nil)
				require.NoError(t, err)

				assert.Equal(t, "https://foo.bar", toURL)
				assert.Equal(t, http.StatusFound, redEH.code)
			},
		},
		"with minimal valid configuration, enforced but not used TLS": {
			enforceTLS: true,
			config:     []byte(`to: http://foo.bar`),
			assert: func(t *testing.T, err error, _ *redirectErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.Contains(t, err.Error(), "'to' scheme must be https")
			},
		},
		"with full valid configuration": {
			config: []byte(`
to: http://foo.bar?origin={{ .Request.URL | urlenc }}
code: 301
`),
			assert: func(t *testing.T, err error, redEH *redirectErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, redEH)
				assert.Equal(t, "with full valid configuration", redEH.ID())

				ctx := mocks.NewRequestContextMock(t)
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
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			es := config.EnforcementSettings{EnforceEgressTLS: tc.enforceTLS}
			validator, err := validation.NewValidator(
				validation.WithTagValidator(es),
				validation.WithErrorTranslator(es),
			)
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			// WHEN
			errorHandler, err := newRedirectErrorHandler(appCtx, uc, conf)

			// THEN
			tc.assert(t, err, errorHandler)
		})
	}
}

func TestCreateRedirectErrorHandlerFromPrototype(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *redirectErrorHandler, configured *redirectErrorHandler)
	}{
		"no new configuration provided": {
			prototypeConfig: []byte(`to: http://foo.bar`),
			assert: func(t *testing.T, err error, prototype *redirectErrorHandler, configured *redirectErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		"empty configuration provided": {
			prototypeConfig: []byte(`to: http://foo.bar`),
			config:          []byte(``),
			assert: func(t *testing.T, err error, prototype *redirectErrorHandler, configured *redirectErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		"unsupported configuration provided": {
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
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			validator, err := validation.NewValidator(
				validation.WithTagValidator(config.EnforcementSettings{}),
			)
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			prototype, err := newRedirectErrorHandler(appCtx, uc, pc)
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

	for uc, tc := range map[string]struct {
		config           []byte
		error            error
		configureContext func(t *testing.T, ctx *mocks.RequestContextMock)
		assert           func(t *testing.T, err error)
	}{
		"with template rendering error": {
			config: []byte(`to: http://foo.bar={{ len .foobar }}`),
			error:  heimdall.ErrAuthentication,
			configureContext: func(t *testing.T, ctx *mocks.RequestContextMock) {
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
		"without return to url templating": {
			config: []byte(`to: http://foo.bar`),
			error:  heimdall.ErrAuthentication,
			configureContext: func(t *testing.T, ctx *mocks.RequestContextMock) {
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
		"with template and code set": {
			config: []byte(`
to: http://foo.bar?origin={{ .Request.URL | urlenc }}
code: 300
`),
			error: heimdall.ErrAuthentication,
			configureContext: func(t *testing.T, ctx *mocks.RequestContextMock) {
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
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			mctx := mocks.NewRequestContextMock(t)
			mctx.EXPECT().Context().Return(t.Context())

			tc.configureContext(t, mctx)

			validator, err := validation.NewValidator(
				validation.WithTagValidator(config.EnforcementSettings{}),
			)
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			errorHandler, err := newRedirectErrorHandler(appCtx, "foo", conf)
			require.NoError(t, err)

			// WHEN
			execErr := errorHandler.Execute(mctx, tc.error)

			// THEN
			tc.assert(t, execErr)
		})
	}
}
