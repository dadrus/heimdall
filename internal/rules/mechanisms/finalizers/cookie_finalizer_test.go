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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCreateCookieFinalizer(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		id     string
		config []byte
		assert func(t *testing.T, err error, finalizer *cookieFinalizer)
	}{
		{
			uc: "without configuration",
			assert: func(t *testing.T, err error, _ *cookieFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'cookies' is a required field")
			},
		},
		{
			uc:     "with empty cookies configuration",
			config: []byte(`cookies: {}`),
			assert: func(t *testing.T, err error, _ *cookieFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'cookies' must contain more than 0 items")
			},
		},
		{
			uc: "with unsupported attributes",
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
		{
			uc: "with bad template",
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
		{
			uc: "with valid config",
			id: "cun",
			config: []byte(`
cookies:
  foo: bar
  bar: "{{ .Subject.ID }}"`),
			assert: func(t *testing.T, err error, finalizer *cookieFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, finalizer.cookies, 2)
				assert.Equal(t, "cun", finalizer.ID())

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
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			finalizer, err := newCookieFinalizer(tc.id, conf)

			// THEN
			tc.assert(t, err, finalizer)
		})
	}
}

func TestCreateCookieFinalizerFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		id              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *cookieFinalizer, configured *cookieFinalizer)
	}{
		{
			uc: "no new configuration provided",
			id: "cun1",
			prototypeConfig: []byte(`
cookies:
  foo: bar
`),
			assert: func(t *testing.T, err error, prototype *cookieFinalizer, configured *cookieFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "cun1", configured.ID())
			},
		},
		{
			uc: "configuration without cookies provided",
			id: "cun2",
			prototypeConfig: []byte(`
cookies:
  foo: bar
`),
			config: []byte(``),
			assert: func(t *testing.T, err error, prototype *cookieFinalizer, configured *cookieFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "cun2", configured.ID())
			},
		},
		{
			uc: "new cookies provided",
			id: "cun3",
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
				assert.Equal(t, "cun3", configured.ID())
				assert.Equal(t, prototype.ID(), configured.ID())

				val, err := configured.cookies["bar"].Render(nil)
				require.NoError(t, err)
				assert.Equal(t, "foo", val)

				assert.False(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newCookieFinalizer(tc.id, pc)
			require.NoError(t, err)

			// WHEN
			finalizer, err := prototype.WithConfig(conf)

			// THEN
			realFinalizer, ok := finalizer.(*cookieFinalizer)
			require.True(t, ok)

			tc.assert(t, err, prototype, realFinalizer)
		})
	}
}

func TestCookieFinalizerExecute(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc               string
		id               string
		config           []byte
		configureContext func(t *testing.T, ctx *mocks.ContextMock)
		createSubject    func(t *testing.T) *subject.Subject
		assert           func(t *testing.T, err error)
	}{
		{
			uc: "with nil subject",
			id: "cun1",
			config: []byte(`
cookies:
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
				assert.Equal(t, "cun1", identifier.ID())
			},
		},
		{
			uc: "with all preconditions satisfied",
			config: []byte(`
cookies:
  foo: "{{ .Subject.Attributes.bar }}"
  bar: "{{ .Subject.ID }}"
  baz: bar
  x_foo: '{{ .Request.Header "X-Foo" }}'
  x_bar: '{{ .Outputs.foo }}'
`),
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
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
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			createSubject := x.IfThenElse(tc.createSubject != nil,
				tc.createSubject,
				func(t *testing.T) *subject.Subject {
					t.Helper()

					return nil
				})

			configureContext := x.IfThenElse(tc.configureContext != nil,
				tc.configureContext,
				func(t *testing.T, _ *mocks.ContextMock) { t.Helper() })

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			mctx := mocks.NewContextMock(t)
			mctx.EXPECT().AppContext().Return(context.Background())

			sub := createSubject(t)

			configureContext(t, mctx)

			finalizer, err := newCookieFinalizer(tc.id, conf)
			require.NoError(t, err)

			// WHEN
			err = finalizer.Execute(mctx, sub)

			// THEN
			tc.assert(t, err)
		})
	}
}
