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

func TestCreateHeaderFinalizer(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		id     string
		config []byte
		assert func(t *testing.T, err error, finalizer *headerFinalizer)
	}{
		{
			uc: "without configuration",
			assert: func(t *testing.T, err error, _ *headerFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'headers' is a required field")
			},
		},
		{
			uc:     "with empty headers configuration",
			config: []byte(`headers: {}`),
			assert: func(t *testing.T, err error, _ *headerFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'headers' must contain more than 0 items")
			},
		},
		{
			uc: "with unsupported attributes",
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
		{
			uc: "with bad template",
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
		{
			uc: "with valid config",
			id: "hun",
			config: []byte(`
headers:
  foo: bar
  bar: "{{ .Subject.ID }}"`),
			assert: func(t *testing.T, err error, finalizer *headerFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, finalizer.headers, 2)
				assert.Equal(t, "hun", finalizer.ID())

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
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			finalizer, err := newHeaderFinalizer(tc.id, conf)

			// THEN
			tc.assert(t, err, finalizer)
		})
	}
}

func TestCreateHeaderFinalizerFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		id              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *headerFinalizer, configured *headerFinalizer)
	}{
		{
			uc: "no new configuration provided",
			id: "hun1",
			prototypeConfig: []byte(`
headers:
  foo: bar
`),
			assert: func(t *testing.T, err error, prototype *headerFinalizer, configured *headerFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "hun1", configured.ID())
			},
		},
		{
			uc: "configuration without headers provided",
			id: "hun2",
			prototypeConfig: []byte(`
headers:
  foo: bar
`),
			config: []byte(``),
			assert: func(t *testing.T, err error, prototype *headerFinalizer, configured *headerFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "hun2", configured.ID())
			},
		},
		{
			uc: "new headers provided",
			id: "hun3",
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
				assert.Equal(t, "hun3", configured.ID())
				assert.Equal(t, prototype.ID(), configured.ID())

				val, err := configured.headers["bar"].Render(nil)
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

			prototype, err := newHeaderFinalizer(tc.id, pc)
			require.NoError(t, err)

			// WHEN
			finalizer, err := prototype.WithConfig(conf)

			// THEN
			realFinalizer, ok := finalizer.(*headerFinalizer)
			require.True(t, ok)

			tc.assert(t, err, prototype, realFinalizer)
		})
	}
}

func TestHeaderFinalizerExecute(t *testing.T) {
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
			id: "hun1",
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
				assert.Equal(t, "hun1", identifier.ID())
			},
		},
		{
			uc: "with all preconditions satisfied",
			config: []byte(`
headers:
  foo: "{{ .Subject.Attributes.bar }}"
  bar: "{{ .Subject.ID }}"
  baz: bar
  X-Baz: '{{ .Request.Header "X-Foo" }}'
  X-Foo: '{{ .Outputs.foo }}'
`),
			configureContext: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				reqf := mocks.NewRequestFunctionsMock(t)
				reqf.EXPECT().Header("X-Foo").Return("Bar")

				ctx.EXPECT().AddHeaderForUpstream("foo", "baz")
				ctx.EXPECT().AddHeaderForUpstream("bar", "FooBar")
				ctx.EXPECT().AddHeaderForUpstream("baz", "bar")
				ctx.EXPECT().AddHeaderForUpstream("X-Baz", "Bar")
				ctx.EXPECT().AddHeaderForUpstream("X-Foo", "bar")
				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: reqf})
				ctx.EXPECT().Outputs().Return(heimdall.Outputs{"foo": "bar"})
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

			ctx := mocks.NewContextMock(t)
			ctx.EXPECT().AppContext().Return(context.Background()).Maybe()

			sub := createSubject(t)

			configureContext(t, ctx)

			finalizer, err := newHeaderFinalizer(tc.id, conf)
			require.NoError(t, err)

			// WHEN
			err = finalizer.Execute(ctx, sub)

			// THEN
			tc.assert(t, err)
		})
	}
}
