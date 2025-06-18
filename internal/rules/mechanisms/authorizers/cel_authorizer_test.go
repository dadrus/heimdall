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

package authorizers

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCreateCELAuthorizer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config []byte
		assert func(t *testing.T, err error, auth *celAuthorizer)
	}{
		"without configuration": {
			assert: func(t *testing.T, err error, _ *celAuthorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'expressions' is a required field")
			},
		},
		"without rules": {
			config: []byte(`expressions: []`),
			assert: func(t *testing.T, err error, _ *celAuthorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'expressions' must contain more than 0 items")
			},
		},
		"with malformed expressions": {
			config: []byte(`
expressions: 
  - expression: "foo()"
`),
			assert: func(t *testing.T, err error, _ *celAuthorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to compile")
			},
		},
		"with expression, which doesn't return bool value": {
			config: []byte(`
expressions: 
  - expression: "size(Subject.ID)"
`),
			assert: func(t *testing.T, err error, _ *celAuthorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "wanted bool")
			},
		},
		"with unsupported attributes": {
			config: []byte(`
expressions:
  - expression: "has(Subject.ID)"
    message: bar
foo: bar
`),
			assert: func(t *testing.T, err error, _ *celAuthorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		"with expression list without expression value": {
			config: []byte(`
expressions:
  - message: bar
`),
			assert: func(t *testing.T, err error, _ *celAuthorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'expressions'[0].'expression' is a required field")
			},
		},
		"with minimal valid configuration": {
			config: []byte(`
expressions:
  - expression: "has(Subject.ID)"
    message: Subject ID is not present
`),
			assert: func(t *testing.T, err error, auth *celAuthorizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "with minimal valid configuration", auth.ID())
				assert.NotNil(t, auth.celEnv)
				assert.NotEmpty(t, auth.expressions)
				assert.Empty(t, auth.v)
				assert.False(t, auth.ContinueOnError())
			},
		},
		"with full configuration": {
			config: []byte(`
values:
  foo: "{{ .Subject.Attributes.foo }}"
expressions:
  - expression: "has(Subject.ID)"
    message: Subject ID is not present
`),
			assert: func(t *testing.T, err error, auth *celAuthorizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "with full configuration", auth.ID())
				assert.NotNil(t, auth.celEnv)
				assert.NotEmpty(t, auth.expressions)
				assert.Len(t, auth.v, 1)
				assert.False(t, auth.ContinueOnError())
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
			a, err := newCELAuthorizer(appCtx, uc, conf)

			// THEN
			tc.assert(t, err, a)
		})
	}
}

func TestCreateCELAuthorizerFromPrototype(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *celAuthorizer, configured *celAuthorizer)
	}{
		"no new configuration provided": {
			prototypeConfig: []byte(`
values:
  foo: bar
expressions: 
  - expression: "Request.URL.Scheme == 'http'"
`),
			assert: func(t *testing.T, err error, prototype *celAuthorizer, configured *celAuthorizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		"new values provided": {
			prototypeConfig: []byte(`
values:
  foo: bar
expressions: 
  - expression: "Request.URL.Scheme == 'http'"
`),
			config: []byte(`
values:
  foo: foo
`),
			assert: func(t *testing.T, err error, prototype *celAuthorizer, configured *celAuthorizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				require.NotNil(t, configured)
				assert.Equal(t, prototype.expressions, configured.expressions)
				assert.Equal(t, prototype.celEnv, configured.celEnv)
				assert.NotEqual(t, prototype.v, configured.v)
				assert.Len(t, configured.v, 1)
				assert.Equal(t, "new values provided", configured.ID())
				assert.False(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
			},
		},
		"new expressions provided": {
			prototypeConfig: []byte(`
values:
  foo: bar
expressions: 
  - expression: "Request.URL.Scheme == 'http'"
`),
			config: []byte(`
expressions: 
  - expression: "Request.Header('X-Foo-Bar') == 'Baz'"
`),
			assert: func(t *testing.T, err error, prototype *celAuthorizer, configured *celAuthorizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				require.NotNil(t, configured)
				assert.NotEqual(t, prototype.expressions, configured.expressions)
				assert.Equal(t, prototype.celEnv, configured.celEnv)
				assert.Equal(t, prototype.v, configured.v)
				assert.Equal(t, "new expressions provided", configured.ID())
				assert.False(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
			},
		},
		"malformed values": {
			prototypeConfig: []byte(`
expressions: 
  - expression: "Request.URL.Scheme == 'http'"
`),
			config: []byte(`
values:
  foo: "{{ foo.bar }}"
`),
			assert: func(t *testing.T, err error, prototype *celAuthorizer, _ *celAuthorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed to parse template")

				require.NotNil(t, prototype)
			},
		},
		"malformed expressions": {
			prototypeConfig: []byte(`
expressions: 
  - expression: "Request.URL.Scheme == 'http'"
`),
			config: []byte(`
expressions: 
  - expression: "foo()"
`),
			assert: func(t *testing.T, err error, prototype *celAuthorizer, _ *celAuthorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed to compile")

				require.NotNil(t, prototype)
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

			prototype, err := newCELAuthorizer(appCtx, uc, pc)
			require.NoError(t, err)

			// WHEN
			auth, err := prototype.WithConfig(conf)

			// THEN
			var (
				locAuth *celAuthorizer
				ok      bool
			)

			if err == nil {
				locAuth, ok = auth.(*celAuthorizer)
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, locAuth)
		})
	}
}

func TestCELAuthorizerExecute(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config                     []byte
		configureContextAndSubject func(t *testing.T, ctx *mocks.RequestContextMock, sub *subject.Subject)
		assert                     func(t *testing.T, err error)
	}{
		"denied by expression without access to subject and request": {
			config: []byte(`
expressions:
  - expression: "true == false"
`),
			configureContextAndSubject: func(t *testing.T, ctx *mocks.RequestContextMock, _ *subject.Subject) {
				// nothing is required here
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
				ctx.EXPECT().Outputs().Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthorization)
				assert.Contains(t, err.Error(), "expression 1 failed")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "denied by expression without access to subject and request", identifier.ID())
			},
		},
		"failed rendering values": {
			config: []byte(`
values:
  foo: "{{ len .foo }}"
expressions:
  - expression: "true == true"
`),
			configureContextAndSubject: func(t *testing.T, ctx *mocks.RequestContextMock, _ *subject.Subject) {
				// nothing is required here
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
				ctx.EXPECT().Outputs().Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to render values")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "failed rendering values", identifier.ID())
			},
		},
		"expressions can use subject, request, outputs, and values properties": {
			config: []byte(`
values:
  foo: bar
expressions:
  - expression: |
      Subject.Attributes.exists(c, c.startsWith('group'))
        && Subject.Attributes
          .filter(c, c.startsWith('group'))
          .all(c, Subject.Attributes[c]
          .all(g, g.endsWith('@acme.co')))
  - expression: Request.Method == 'GET'
  - expression: Request.URL.Scheme == 'http'
  - expression: Request.URL.Host == 'localhost'
  - expression: Request.URL.Path == '/test'
  - expression: size(Request.URL.Query()) == 2
  - expression: Request.URL.Query().foo == ["bar"]
  - expression: Request.Header('X-Custom-Header') == "foobar"
  - expression: Request.ClientIPAddresses.exists_one(v, v == '127.0.0.1')
  - expression: Request.Cookie("FooCookie") == "barfoo"
  - expression: Request.URL.String() == "http://localhost/test?foo=bar&baz=zab"
  - expression: Request.URL.Path.split("/").last() == "test"
  - expression: Request.URL.Captures.foo == "bar"
  - expression: Outputs.foo == "bar"
  - expression: Values.foo == "bar"
`),
			configureContextAndSubject: func(t *testing.T, ctx *mocks.RequestContextMock, sub *subject.Subject) {
				t.Helper()

				sub.ID = "foobar"
				sub.Attributes = map[string]any{
					"group1": []string{"admin@acme.co", "analyst@acme.co"},
					"labels": []string{"metadata", "prod", "pii"},
					"groupN": []string{"forever@acme.co"},
				}

				reqf := mocks.NewRequestFunctionsMock(t)
				reqf.EXPECT().Header("X-Custom-Header").Return("foobar")
				reqf.EXPECT().Cookie("FooCookie").Return("barfoo")

				ctx.EXPECT().Request().Return(&heimdall.Request{
					RequestFunctions: reqf,
					Method:           http.MethodGet,
					URL: &heimdall.URL{
						URL: url.URL{
							Scheme:   "http",
							Host:     "localhost",
							Path:     "/test",
							RawQuery: "foo=bar&baz=zab",
						},
						Captures: map[string]string{"foo": "bar"},
					},
					ClientIPAddresses: []string{"127.0.0.1", "10.10.10.10"},
				})

				ctx.EXPECT().Outputs().Return(map[string]any{"foo": "bar"})
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

			ctx := mocks.NewRequestContextMock(t)
			ctx.EXPECT().Context().Return(t.Context())

			sub := &subject.Subject{}

			tc.configureContextAndSubject(t, ctx, sub)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			auth, err := newCELAuthorizer(appCtx, uc, conf)
			require.NoError(t, err)

			// WHEN
			err = auth.Execute(ctx, sub)

			// THEN
			tc.assert(t, err)
		})
	}
}
