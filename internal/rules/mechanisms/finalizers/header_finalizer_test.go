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
	"context"
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

func TestCreateHeaderFinalizer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config []byte
		assert func(t *testing.T, err error, finalizer *headerFinalizer)
	}{
		"without configuration": {
			assert: func(t *testing.T, err error, _ *headerFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'headers' is a required field")
			},
		},
		"with empty headers configuration": {
			config: []byte(`headers: {}`),
			assert: func(t *testing.T, err error, _ *headerFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'headers' must contain more than 0 items")
			},
		},
		"with unsupported attributes": {
			config: []byte(`
headers:
  foo: bar
foo: bar
`),
			assert: func(t *testing.T, err error, _ *headerFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		"with bad template": {
			config: []byte(`
headers:
  bar: "{{ .Subject.ID | foobar }}"
`),
			assert: func(t *testing.T, err error, _ *headerFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		"with valid config": {
			config: []byte(`
headers:
  foo: bar
  bar: "{{ .Subject.ID }}"`),
			assert: func(t *testing.T, err error, finalizer *headerFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, finalizer.headers, 2)
				assert.Equal(t, "with valid config", finalizer.ID())

				val, err := finalizer.headers["foo"].Render(nil)
				require.NoError(t, err)
				assert.Equal(t, "bar", val)

				val, err = finalizer.headers["bar"].Render(map[string]any{
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
			finalizer, err := newHeaderFinalizer(appCtx, uc, conf)

			// THEN
			tc.assert(t, err, finalizer)
		})
	}
}

func TestCreateHeaderFinalizerFromPrototype(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *headerFinalizer, configured *headerFinalizer)
	}{
		"no new configuration provided": {
			prototypeConfig: []byte(`
headers:
  foo: bar
`),
			assert: func(t *testing.T, err error, prototype *headerFinalizer, configured *headerFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "no new configuration provided", configured.ID())
			},
		},
		"configuration without headers provided": {
			prototypeConfig: []byte(`
headers:
  foo: bar
`),
			config: []byte(``),
			assert: func(t *testing.T, err error, prototype *headerFinalizer, configured *headerFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "configuration without headers provided", configured.ID())
			},
		},
		"new headers provided": {
			prototypeConfig: []byte(`
headers:
  foo: bar
`),
			config: []byte(`
headers:
  bar: foo
`),
			assert: func(t *testing.T, err error, prototype *headerFinalizer, configured *headerFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				require.NotNil(t, configured)
				assert.NotEmpty(t, configured.headers)
				assert.Equal(t, "new headers provided", configured.ID())
				assert.Equal(t, prototype.ID(), configured.ID())

				val, err := configured.headers["bar"].Render(nil)
				require.NoError(t, err)
				assert.Equal(t, "foo", val)

				assert.False(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
			},
		},
		"with unsupported attributes": {
			prototypeConfig: []byte(`
headers:
  foo: bar
`),
			config: []byte(`
headers:
  bar: foo
foo: bar
`),
			assert: func(t *testing.T, err error, prototype *headerFinalizer, _ *headerFinalizer) {
				t.Helper()

				assert.NotNil(t, prototype)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
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

			prototype, err := newHeaderFinalizer(appCtx, uc, pc)
			require.NoError(t, err)

			// WHEN
			finalizer, err := prototype.WithConfig(conf)

			// THEN
			var (
				realFinalizer *headerFinalizer
				ok            bool
			)

			if err == nil {
				realFinalizer, ok = finalizer.(*headerFinalizer)
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, realFinalizer)
		})
	}
}

func TestHeaderFinalizerExecute(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config           []byte
		subject          *subject.Subject
		configureContext func(t *testing.T, ctx *mocks.RequestContextMock)
		assert           func(t *testing.T, err error)
	}{
		"with nil subject": {
			config: []byte(`
headers:
  foo: bar
  bar: "{{ .Subject.ID }}"
`),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "'nil' subject")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "with nil subject", identifier.ID())
			},
		},
		"template rendering error": {
			config: []byte(`
headers:
  X-Baz: '{{ .Request.Foo "X-Foo" }}'
`),
			configureContext: func(t *testing.T, ctx *mocks.RequestContextMock) {
				t.Helper()

				reqf := mocks.NewRequestFunctionsMock(t)

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: reqf})
				ctx.EXPECT().Outputs().Return(map[string]any{"foo": "bar"})
			},
			subject: &subject.Subject{ID: "FooBar", Attributes: map[string]any{}},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to render value for 'X-Baz' header")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "template rendering error", identifier.ID())
			},
		},
		"with all preconditions satisfied": {
			config: []byte(`
headers:
  foo: "{{ .Subject.Attributes.bar }}"
  bar: "{{ .Subject.ID }}"
  baz: bar
  X-Baz: '{{ .Request.Header "X-Foo" }}'
  X-Foo: '{{ .Outputs.foo }}'
`),
			configureContext: func(t *testing.T, ctx *mocks.RequestContextMock) {
				t.Helper()

				reqf := mocks.NewRequestFunctionsMock(t)
				reqf.EXPECT().Header("X-Foo").Return("Bar")

				ctx.EXPECT().AddHeaderForUpstream("foo", "baz")
				ctx.EXPECT().AddHeaderForUpstream("bar", "FooBar")
				ctx.EXPECT().AddHeaderForUpstream("baz", "bar")
				ctx.EXPECT().AddHeaderForUpstream("X-Baz", "Bar")
				ctx.EXPECT().AddHeaderForUpstream("X-Foo", "bar")
				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: reqf})
				ctx.EXPECT().Outputs().Return(map[string]any{"foo": "bar"})
			},
			subject: &subject.Subject{ID: "FooBar", Attributes: map[string]any{"bar": "baz"}},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			configureContext := x.IfThenElse(tc.configureContext != nil,
				tc.configureContext,
				func(t *testing.T, _ *mocks.RequestContextMock) { t.Helper() })

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			ctx := mocks.NewRequestContextMock(t)
			ctx.EXPECT().Context().Return(context.Background()).Maybe()

			configureContext(t, ctx)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			finalizer, err := newHeaderFinalizer(appCtx, uc, conf)
			require.NoError(t, err)

			// WHEN
			err = finalizer.Execute(ctx, tc.subject)

			// THEN
			tc.assert(t, err)
		})
	}
}
