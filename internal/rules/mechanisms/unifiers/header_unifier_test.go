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

package unifiers

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCreateHeaderUnifier(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		id     string
		config []byte
		assert func(t *testing.T, err error, unifier *headerUnifier)
	}{
		{
			uc: "without configuration",
			assert: func(t *testing.T, err error, _ *headerUnifier) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no header")
			},
		},
		{
			uc:     "without header configuration",
			config: []byte(``),
			assert: func(t *testing.T, err error, _ *headerUnifier) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no header")
			},
		},
		{
			uc: "with unsupported attributes",
			config: []byte(`
headers:
  foo: bar
foo: bar
`),
			assert: func(t *testing.T, err error, _ *headerUnifier) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
		{
			uc: "with bad template",
			config: []byte(`
headers:
  bar: "{{ .Subject.ID | foobar }}"
`),
			assert: func(t *testing.T, err error, _ *headerUnifier) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
		{
			uc: "with valid config",
			id: "hun",
			config: []byte(`
headers:
  foo: bar
  bar: "{{ .Subject.ID }}"`),
			assert: func(t *testing.T, err error, unifier *headerUnifier) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, unifier.headers, 2)
				assert.Equal(t, "hun", unifier.HandlerID())

				val, err := unifier.headers["foo"].Render(nil, nil)
				require.NoError(t, err)
				assert.Equal(t, "bar", val)

				val, err = unifier.headers["bar"].Render(nil, &subject.Subject{ID: "baz"})
				require.NoError(t, err)
				assert.Equal(t, "baz", val)

				assert.False(t, unifier.ContinueOnError())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			unifier, err := newHeaderUnifier(tc.id, conf)

			// THEN
			tc.assert(t, err, unifier)
		})
	}
}

func TestCreateHeaderUnifierFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		id              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *headerUnifier, configured *headerUnifier)
	}{
		{
			uc: "no new configuration provided",
			id: "hun1",
			prototypeConfig: []byte(`
headers:
  foo: bar
`),
			assert: func(t *testing.T, err error, prototype *headerUnifier, configured *headerUnifier) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "hun1", configured.HandlerID())
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
			assert: func(t *testing.T, err error, prototype *headerUnifier, configured *headerUnifier) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "hun2", configured.HandlerID())
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
			assert: func(t *testing.T, err error, prototype *headerUnifier, configured *headerUnifier) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				require.NotNil(t, configured)
				assert.NotEmpty(t, configured.headers)
				assert.Equal(t, "hun3", configured.HandlerID())
				assert.Equal(t, prototype.HandlerID(), configured.HandlerID())

				val, err := configured.headers["bar"].Render(nil, nil)
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

			prototype, err := newHeaderUnifier(tc.id, pc)
			require.NoError(t, err)

			// WHEN
			unifier, err := prototype.WithConfig(conf)

			// THEN
			headerUnifier, ok := unifier.(*headerUnifier)
			require.True(t, ok)

			tc.assert(t, err, prototype, headerUnifier)
		})
	}
}

func TestHeaderUnifierExecute(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc               string
		id               string
		config           []byte
		configureContext func(t *testing.T, ctx *mocks.MockContext)
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
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "'nil' subject")

				var identifier interface{ HandlerID() string }
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "hun1", identifier.HandlerID())
			},
		},
		{
			uc: "with all preconditions satisfied",
			config: []byte(`
headers:
  foo: "{{ .Subject.Attributes.bar }}"
  bar: "{{ .Subject.ID }}"
  baz: bar
`),
			configureContext: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("AddHeaderForUpstream", "foo", "baz")
				ctx.On("AddHeaderForUpstream", "bar", "FooBar")
				ctx.On("AddHeaderForUpstream", "baz", "bar")
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
				func(t *testing.T, ctx *mocks.MockContext) { t.Helper() })

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			mctx := &mocks.MockContext{}
			mctx.On("AppContext").Return(context.Background())

			sub := createSubject(t)

			configureContext(t, mctx)

			unifier, err := newHeaderUnifier(tc.id, conf)
			require.NoError(t, err)

			// WHEN
			err = unifier.Execute(mctx, sub)

			// THEN
			tc.assert(t, err)

			mctx.AssertExpectations(t)
		})
	}
}
