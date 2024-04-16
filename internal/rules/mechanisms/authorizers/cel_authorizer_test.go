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
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCreateCELAuthorizer(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		id     string
		config []byte
		assert func(t *testing.T, err error, auth *celAuthorizer)
	}{
		{
			uc: "without configuration",
			assert: func(t *testing.T, err error, _ *celAuthorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'expressions' is a required field")
			},
		},
		{
			uc:     "without rules",
			config: []byte(`expressions: []`),
			assert: func(t *testing.T, err error, _ *celAuthorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'expressions' must contain more than 0 items")
			},
		},
		{
			uc: "with malformed expressions",
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
		{
			uc: "with expression, which doesn't return bool value",
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
		{
			uc: "with unsupported attributes",
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
		{
			uc: "with expression list without expression value",
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
		{
			uc: "with valid expression",
			id: "authz",
			config: []byte(`
expressions:
  - expression: "has(Subject.ID)"
    message: Subject ID is not present
`),
			assert: func(t *testing.T, err error, auth *celAuthorizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "authz", auth.ID())
				assert.NotEmpty(t, auth.expressions)
				assert.False(t, auth.ContinueOnError())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			a, err := newCELAuthorizer(tc.id, conf)

			// THEN
			tc.assert(t, err, a)
		})
	}
}

func TestCreateCELAuthorizerFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		id              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *celAuthorizer, configured *celAuthorizer)
	}{
		{
			uc: "no new configuration provided",
			prototypeConfig: []byte(`
expressions: 
  - expression: "Request.URL.Scheme == 'http'"
`),
			assert: func(t *testing.T, err error, prototype *celAuthorizer, configured *celAuthorizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc: "configuration without expressions provided",
			prototypeConfig: []byte(`
expressions: 
  - expression: "Request.URL.Scheme == 'http'"
`),
			config: []byte(``),
			assert: func(t *testing.T, err error, prototype *celAuthorizer, configured *celAuthorizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc: "new expressions provided",
			id: "authz",
			prototypeConfig: []byte(`
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
				assert.Equal(t, "authz", configured.ID())
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

			prototype, err := newCELAuthorizer(tc.id, pc)
			require.NoError(t, err)

			// WHEN
			auth, err := prototype.WithConfig(conf)

			// THEN
			locAuth, ok := auth.(*celAuthorizer)
			require.True(t, ok)

			tc.assert(t, err, prototype, locAuth)
		})
	}
}

func TestCELAuthorizerExecute(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc                         string
		id                         string
		config                     []byte
		configureContextAndSubject func(t *testing.T, ctx *mocks.ContextMock, sub *subject.Subject)
		assert                     func(t *testing.T, err error)
	}{
		{
			uc: "denied by expression without access to subject and request",
			id: "authz1",
			config: []byte(`
expressions:
  - expression: "true == false"
`),
			configureContextAndSubject: func(t *testing.T, ctx *mocks.ContextMock, _ *subject.Subject) {
				// nothing is required here
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthorization)
				assert.Contains(t, err.Error(), "expression 1 failed")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "authz1", identifier.ID())
			},
		},
		{
			uc: "expressions can use subject and request properties",
			id: "authz2",
			config: []byte(`
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
`),
			configureContextAndSubject: func(t *testing.T, ctx *mocks.ContextMock, sub *subject.Subject) {
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

			ctx := mocks.NewContextMock(t)
			ctx.EXPECT().AppContext().Return(context.Background())

			sub := &subject.Subject{}

			tc.configureContextAndSubject(t, ctx, sub)

			auth, err := newCELAuthorizer(tc.id, conf)
			require.NoError(t, err)

			// WHEN
			err = auth.Execute(ctx, sub)

			// THEN
			tc.assert(t, err)
		})
	}
}
