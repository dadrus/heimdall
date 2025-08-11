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

package finalizers

import (
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCreateCookieFinalizer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config []byte
		assert func(t *testing.T, err error, finalizer *cookieFinalizer)
	}{
		"without configuration": {
			assert: func(t *testing.T, err error, _ *cookieFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'cookies' is a required field")
			},
		},
		"with empty cookies configuration": {
			config: []byte(`cookies: {}`),
			assert: func(t *testing.T, err error, _ *cookieFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'cookies' must contain more than 0 items")
			},
		},
		"with unsupported attributes": {
			config: []byte(`
cookies:
  foo: bar
foo: bar
`),
			assert: func(t *testing.T, err error, _ *cookieFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		"with bad template": {
			config: []byte(`
cookies:
  bar: "{{ .Subject.ID | foobar }}"
`),
			assert: func(t *testing.T, err error, finalizer *cookieFinalizer) {
				t.Helper()

				require.Nil(t, finalizer)
				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		"with valid config": {
			config: []byte(`
cookies:
  foo: bar
  bar: "{{ .Subject.ID }}"`),
			assert: func(t *testing.T, err error, finalizer *cookieFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, finalizer.cookies, 2)
				assert.Equal(t, "with valid config", finalizer.ID())
				assert.Equal(t, finalizer.Name(), finalizer.ID())

				val, err := finalizer.cookies["foo"].Render(nil)
				require.NoError(t, err)
				assert.Equal(t, "bar", val)

				val, err = finalizer.cookies["bar"].Render(map[string]any{
					"Subject": &subject.Subject{ID: "baz"},
				})
				require.NoError(t, err)
				assert.Equal(t, "baz", val)

				assert.False(t, finalizer.ContinueOnError())
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
			finalizer, err := newCookieFinalizer(appCtx, uc, conf)

			// THEN
			tc.assert(t, err, finalizer)
		})
	}
}

func TestCreateCookieFinalizerFromPrototype(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		prototypeConfig []byte
		config          []byte
		stepID          string
		assert          func(t *testing.T, err error, prototype *cookieFinalizer, configured *cookieFinalizer)
	}{
		"no new configuration and no step ID": {
			prototypeConfig: []byte(`
cookies:
  foo: bar
`),
			assert: func(t *testing.T, err error, prototype *cookieFinalizer, configured *cookieFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		"no new configuration but with step ID": {
			prototypeConfig: []byte(`
cookies:
  foo: bar
`),
			stepID: "foo",
			assert: func(t *testing.T, err error, prototype *cookieFinalizer, configured *cookieFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, "foo", configured.ID())
				assert.Equal(t, prototype.cookies, configured.cookies)
				assert.Equal(t, prototype.app, configured.app)
			},
		},
		"new cookies provided": {
			prototypeConfig: []byte(`
cookies:
  foo: bar
`),
			config: []byte(`
cookies:
  bar: foo
`),
			assert: func(t *testing.T, err error, prototype *cookieFinalizer, configured *cookieFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				require.NotNil(t, configured)
				assert.NotEmpty(t, configured.cookies)
				assert.Equal(t, "new cookies provided", configured.ID())
				assert.Equal(t, prototype.ID(), configured.ID())

				val, err := configured.cookies["bar"].Render(nil)
				require.NoError(t, err)
				assert.Equal(t, "foo", val)

				assert.False(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
			},
		},
		"new cookies and step ID provided": {
			prototypeConfig: []byte(`
cookies:
  foo: bar
`),
			config: []byte(`
cookies:
  bar: foo
`),
			stepID: "bar",
			assert: func(t *testing.T, err error, prototype *cookieFinalizer, configured *cookieFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				require.NotNil(t, configured)
				assert.NotEmpty(t, configured.cookies)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, prototype.Name(), prototype.ID())
				assert.Equal(t, "bar", configured.ID())

				val, err := configured.cookies["bar"].Render(nil)
				require.NoError(t, err)
				assert.Equal(t, "foo", val)

				assert.False(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
			},
		},
		"empty cookies provided": {
			prototypeConfig: []byte(`
cookies:
  foo: bar
`),
			config: []byte(`cookies: {}`),
			assert: func(t *testing.T, err error, prototype *cookieFinalizer, configured *cookieFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "empty cookies")
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

			prototype, err := newCookieFinalizer(appCtx, uc, pc)
			require.NoError(t, err)

			// WHEN
			finalizer, err := prototype.WithConfig(tc.stepID, conf)

			// THEN
			realFinalizer, ok := finalizer.(*cookieFinalizer)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, realFinalizer)
		})
	}
}

func TestCookieFinalizerExecute(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config           []byte
		configureContext func(t *testing.T, ctx *mocks.RequestContextMock)
		createSubject    func(t *testing.T) *subject.Subject
		assert           func(t *testing.T, err error)
	}{
		"rendering error": {
			config: []byte(`
cookies:
  foo: "{{ .Subject.ID.foo }}"
`),
			configureContext: func(t *testing.T, ctx *mocks.RequestContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: mocks.NewRequestFunctionsMock(t)})
				ctx.EXPECT().Outputs().Return(map[string]any{})
			},
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed to render")
			},
		},
		"all preconditions satisfied": {
			config: []byte(`
cookies:
  foo: "{{ .Subject.Attributes.bar }}"
  bar: "{{ .Subject.ID }}"
  baz: bar
  x_foo: '{{ .Request.Header "X-Foo" }}'
  x_bar: '{{ .Outputs.foo }}'
`),
			configureContext: func(t *testing.T, ctx *mocks.RequestContextMock) {
				t.Helper()

				reqf := mocks.NewRequestFunctionsMock(t)
				reqf.EXPECT().Header("X-Foo").Return("Bar")

				ctx.EXPECT().AddCookieForUpstream("foo", "baz")
				ctx.EXPECT().AddCookieForUpstream("bar", "FooBar")
				ctx.EXPECT().AddCookieForUpstream("baz", "bar")
				ctx.EXPECT().AddCookieForUpstream("x_foo", "Bar")
				ctx.EXPECT().AddCookieForUpstream("x_bar", "bar")
				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: reqf})
				ctx.EXPECT().Outputs().Return(map[string]any{"foo": "bar"})
			},
			createSubject: func(t *testing.T) *subject.Subject {
				t.Helper()

				return &subject.Subject{ID: "FooBar", Attributes: map[string]any{"bar": "baz"}}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			createSubject := x.IfThenElse(tc.createSubject != nil,
				tc.createSubject,
				func(t *testing.T) *subject.Subject {
					t.Helper()

					return &subject.Subject{ID: "foo", Attributes: map[string]any{}}
				})

			configureContext := x.IfThenElse(tc.configureContext != nil,
				tc.configureContext,
				func(t *testing.T, _ *mocks.RequestContextMock) { t.Helper() })

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			mctx := mocks.NewRequestContextMock(t)
			mctx.EXPECT().Context().Return(t.Context())

			sub := createSubject(t)

			configureContext(t, mctx)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			finalizer, err := newCookieFinalizer(appCtx, uc, conf)
			require.NoError(t, err)

			// WHEN
			err = finalizer.Execute(mctx, sub)

			// THEN
			tc.assert(t, err)
		})
	}
}
