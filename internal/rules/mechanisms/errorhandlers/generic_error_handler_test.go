// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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
	"errors"
	"net/url"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/pipeline/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewGenericErrorHandler(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config []byte
		assert func(t *testing.T, err error, eh *genericErrorHandler)
	}{
		"without required code": {
			assert: func(t *testing.T, err error, _ *genericErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "'code' is a required field")
			},
		},
		"with unsupported fields": {
			config: []byte(`
code: 500
foo: bar
`),
			assert: func(t *testing.T, err error, eh *genericErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, eh)
				assert.Equal(t, "with unsupported fields", eh.ID())
				assert.Equal(t, eh.Name(), eh.ID())
				assert.Equal(t, 500, eh.code)
				assert.Nil(t, eh.header)
				assert.Nil(t, eh.body)
				assert.Nil(t, eh.values)
				assert.Equal(t, types.KindErrorHandler, eh.Kind())
				assert.Equal(t, ErrorHandlerGeneric, eh.Type())
			},
		},
		"with full valid configuration": {
			config: []byte(`
code: 418
header:
  X-Request-Host: "{{ .Request.URL.Host }}"
body: "{{ .Values.foo }}"
values:
  foo: bar
`),
			assert: func(t *testing.T, err error, eh *genericErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, eh)
				assert.Equal(t, "with full valid configuration", eh.ID())
				assert.Equal(t, eh.Name(), eh.ID())
				assert.Equal(t, 418, eh.code)
				assert.Len(t, eh.header, 1)
				assert.NotNil(t, eh.body)
				assert.Len(t, eh.values, 1)
				assert.Equal(t, types.KindErrorHandler, eh.Kind())
				assert.Equal(t, ErrorHandlerGeneric, eh.Type())

				reqURL, err := url.Parse("https://foo.bar/baz")
				require.NoError(t, err)

				vals, err := eh.values.Render(map[string]any{
					"Request": &pipeline.Request{URL: &pipeline.URL{URL: *reqURL}},
				})
				require.NoError(t, err)
				assert.Equal(t, map[string]string{"foo": "bar"}, vals)

				header, err := eh.header["X-Request-Host"].Render(map[string]any{
					"Request": &pipeline.Request{URL: &pipeline.URL{URL: *reqURL}},
					"Values":  vals,
				})
				require.NoError(t, err)
				assert.Equal(t, "foo.bar", header)

				body, err := eh.body.Render(map[string]any{"Values": vals})
				require.NoError(t, err)
				assert.Equal(t, "bar", body)
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
			mech, err := newGenericErrorHandler(appCtx, uc, conf)

			// THEN
			eh, ok := mech.(*genericErrorHandler)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, eh)
		})
	}
}

func TestGenericErrorHandlerCreateStep(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config  []byte
		stepDef types.StepDefinition
		assert  func(t *testing.T, err error, prototype, configured *genericErrorHandler)
	}{
		"no new configuration and no step ID": {
			config: []byte(`
code: 401
header:
  X-First: foo
body: bar
values:
  foo: bar
`),
			assert: func(t *testing.T, err error, prototype, configured *genericErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		"no new configuration but with step ID": {
			config: []byte(`
code: 401
header:
  X-First: foo
body: bar
values:
  foo: bar
`),
			stepDef: types.StepDefinition{ID: "bar"},
			assert: func(t *testing.T, err error, prototype, configured *genericErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, "bar", configured.ID())
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, prototype.code, configured.code)
				assert.Equal(t, prototype.header, configured.header)
				assert.Equal(t, prototype.body, configured.body)
				assert.Equal(t, prototype.values, configured.values)
				assert.Equal(t, types.KindErrorHandler, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
			},
		},
		"with malformed configuration": {
			config: []byte(`
code: 401
`),
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"code": "bad"}},
			assert: func(t *testing.T, err error, _, _ *genericErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"with invalid code reconfigured below allowed range": {
			config: []byte(`
code: 401
`),
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"code": 99}},
			assert: func(t *testing.T, err error, _, _ *genericErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "'code' must be 100 or greater")
			},
		},
		"with invalid code reconfigured above allowed range": {
			config: []byte(`
code: 401
`),
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"code": 600}},
			assert: func(t *testing.T, err error, _, _ *genericErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "'code' must be less than 600")
			},
		},
		"with all fields reconfigured": {
			config: []byte(`
code: 401
header:
  X-First: foo
body: "{{ .Values.foo }}"
values:
  foo: bar
`),
			stepDef: types.StepDefinition{
				ID: "baz",
				Config: config.MechanismConfig{
					"code": 403,
					"header": map[string]any{
						"X-Second": "{{ .Values.foo }}",
					},
					"body": "{{ .Values.foo }}",
					"values": map[string]any{
						"foo": "baz",
					},
				},
			},
			assert: func(t *testing.T, err error, prototype, configured *genericErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, configured)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, "baz", configured.ID())
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, 403, configured.code)
				assert.Len(t, configured.header, 1)
				assert.Contains(t, configured.header, "X-Second")
				assert.NotContains(t, configured.header, "X-First")
				assert.NotEqual(t, prototype.body, configured.body)
				assert.Equal(t, types.KindErrorHandler, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())

				vals, err := configured.values.Render(map[string]any{
					"Request": nil,
				})
				require.NoError(t, err)
				assert.Equal(t, map[string]string{"foo": "baz"}, vals)

				header, err := configured.header["X-Second"].Render(map[string]any{
					"Request": nil,
					"Values":  vals,
				})
				require.NoError(t, err)
				assert.Equal(t, "baz", header)

				body, err := configured.body.Render(map[string]any{"Values": vals})
				require.NoError(t, err)
				assert.Equal(t, "baz", body)
			},
		},
		"with values reconfigured only": {
			config: []byte(`
code: 401
header:
  X-First: foo
body: "{{ .Values.foo }}"
values:
  foo: bar
`),
			stepDef: types.StepDefinition{
				Config: config.MechanismConfig{
					"values": map[string]any{
						"zab": "qux",
					},
				},
			},
			assert: func(t *testing.T, err error, prototype, configured *genericErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.Equal(t, prototype.code, configured.code)
				assert.Equal(t, prototype.header, configured.header)
				assert.Equal(t, prototype.body, configured.body)
				assert.Equal(t, types.KindErrorHandler, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())

				vals, err := configured.values.Render(map[string]any{
					"Request": nil,
				})
				require.NoError(t, err)
				assert.Equal(t, map[string]string{"foo": "bar", "zab": "qux"}, vals)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			pc, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			mech, err := newGenericErrorHandler(appCtx, uc, pc)
			require.NoError(t, err)

			configured, ok := mech.(*genericErrorHandler)
			require.True(t, ok)

			// WHEN
			step, err := mech.CreateStep(tc.stepDef)

			// THEN
			eh, ok := step.(*genericErrorHandler)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, configured, eh)
		})
	}
}

func TestGenericErrorHandlerExecute(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config           []byte
		configureContext func(t *testing.T, ctx *mocks.ContextMock)
		assert           func(t *testing.T, err error)
	}{
		"with code only": {
			config: []byte(`
code: 500
`),
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
				ctx.EXPECT().Error().Return(errors.New("test error"))
				ctx.EXPECT().SetError(mock.MatchedBy(func(genErr *pipeline.GenericError) bool {
					t.Helper()

					assert.Equal(t, 500, genErr.Code)
					assert.Nil(t, genErr.Header)
					assert.Empty(t, genErr.Body)
					require.Error(t, genErr.Cause)
					assert.Equal(t, "test error", genErr.Cause.Error())

					return true
				}))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"with code and header": {
			config: []byte(`
code: 500
header:
  X-Error-Reason: blocked
`),
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil).Times(2)
				ctx.EXPECT().Error().Return(errors.New("test error"))
				ctx.EXPECT().SetError(mock.MatchedBy(func(genErr *pipeline.GenericError) bool {
					t.Helper()

					assert.Equal(t, 500, genErr.Code)
					assert.Equal(t, map[string]string{"X-Error-Reason": "blocked"}, genErr.Header)
					assert.Empty(t, genErr.Body)
					require.Error(t, genErr.Cause)
					assert.Equal(t, "test error", genErr.Cause.Error())

					return true
				}))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"with code and body": {
			config: []byte(`
code: 500
body: blocked
`),
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil).Times(2)
				ctx.EXPECT().Error().Return(errors.New("test error"))
				ctx.EXPECT().SetError(mock.MatchedBy(func(genErr *pipeline.GenericError) bool {
					t.Helper()

					assert.Equal(t, 500, genErr.Code)
					assert.Nil(t, genErr.Header)
					assert.Equal(t, "blocked", genErr.Body)
					require.Error(t, genErr.Cause)
					assert.Equal(t, "test error", genErr.Cause.Error())

					return true
				}))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"with values rendering error": {
			config: []byte(`
code: 500
values:
  foo: "{{ len .foobar }}"
`),
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "failed to render values")
			},
		},
		"with header rendering error": {
			config: []byte(`
code: 500
header:
  X-Foo: "{{ .Values.foo.bar }}"
values:
  foo: bar
`),
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil).Times(2)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "failed to render header 'X-Foo'")
			},
		},
		"with body rendering error": {
			config: []byte(`
code: 500
body: "{{ .Values.foo.bar }}"
values:
  foo: bar
`),
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil).Times(2)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "failed to render body")
			},
		},
		"with all rendered attributes": {
			config: []byte(`
code: 451
header:
  X-Auth-Reason: "{{ .Values.reason }}"
  X-Request-Host: "{{ .Request.URL.Host }}"
body: "{{ .Values.reason }} for {{ .Request.URL.Host }}"
values:
  reason: blocked
`),
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				reqURL, err := url.Parse("https://foo.bar/baz")
				require.NoError(t, err)
				req := &pipeline.Request{URL: &pipeline.URL{URL: *reqURL}}

				ctx.EXPECT().Request().Return(req).Times(4)
				ctx.EXPECT().Error().Return(errors.New("test error"))
				ctx.EXPECT().SetError(mock.MatchedBy(func(genErr *pipeline.GenericError) bool {
					t.Helper()

					assert.Equal(t, 451, genErr.Code)
					assert.Equal(t, "blocked for foo.bar", genErr.Body)
					assert.Equal(t, map[string]string{
						"X-Auth-Reason":  "blocked",
						"X-Request-Host": "foo.bar",
					}, genErr.Header)
					require.Error(t, genErr.Cause)
					assert.Equal(t, "test error", genErr.Cause.Error())

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

			mech, err := newGenericErrorHandler(appCtx, "foo", conf)
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

func TestGenericErrorHandlerAccept(t *testing.T) {
	t.Parallel()

	mech := &genericErrorHandler{}

	mech.Accept(nil)
}
