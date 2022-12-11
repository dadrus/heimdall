package authorizers

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/testsupport"
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
			assert: func(t *testing.T, err error, auth *celAuthorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no expressions provided")
			},
		},
		{
			uc:     "without rules",
			config: []byte(``),
			assert: func(t *testing.T, err error, auth *celAuthorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no expressions provided")
			},
		},
		{
			uc: "with malformed expressions",
			config: []byte(`
expressions: 
  - expression: "foo()"
`),
			assert: func(t *testing.T, err error, auth *celAuthorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to compile")
			},
		},
		{
			uc: "with expression, which doesn't return bool value",
			config: []byte(`
expressions: 
  - expression: "size(Subject.ID)"
`),
			assert: func(t *testing.T, err error, auth *celAuthorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
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
			assert: func(t *testing.T, err error, auth *celAuthorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
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
				assert.Equal(t, "authz", auth.HandlerID())
				assert.NotNil(t, auth.env)
				assert.NotEmpty(t, auth.expressions)
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
				assert.Equal(t, "authz", configured.HandlerID())
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
		configureContextAndSubject func(t *testing.T, ctx *mocks.MockContext, sub *subject.Subject)
		assert                     func(t *testing.T, err error)
	}{
		{
			uc: "denied by expression without access to subject and request",
			id: "authz1",
			config: []byte(`
expressions:
  - expression: "true == false"
`),
			configureContextAndSubject: func(t *testing.T, ctx *mocks.MockContext, sub *subject.Subject) {
				// nothing is required here
				t.Helper()

				ctx.On("RequestURL").Return(&url.URL{Scheme: "http", Host: "localhost", Path: "/test"})
				ctx.On("RequestMethod").Return(http.MethodGet)
				ctx.On("RequestClientIPs").Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthorization)
				assert.Contains(t, err.Error(), "expression 1 failed")

				var identifier interface{ HandlerID() string }
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "authz1", identifier.HandlerID())
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
  - expression: size(Request.URL.Query) == 2
  - expression: Request.Header('X-Custom-Header') == "foobar"
  - expression: Request.ClientIP.exists_one(v, v == '127.0.0.1')
`),
			configureContextAndSubject: func(t *testing.T, ctx *mocks.MockContext, sub *subject.Subject) {
				t.Helper()

				sub.ID = "foobar"
				sub.Attributes = map[string]any{
					"group1": []string{"admin@acme.co", "analyst@acme.co"},
					"labels": []string{"metadata", "prod", "pii"},
					"groupN": []string{"forever@acme.co"},
				}

				ctx.On("RequestURL").Return(&url.URL{
					Scheme:   "http",
					Host:     "localhost",
					Path:     "/test",
					RawQuery: "foo=bar&baz=zab",
				})
				ctx.On("RequestMethod").Return(http.MethodGet)
				ctx.On("RequestHeader", "X-Custom-Header").Return("foobar")
				ctx.On("RequestClientIPs").Return([]string{"127.0.0.1", "10.10.10.10"})
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

			mctx := &mocks.MockContext{}
			mctx.On("AppContext").Return(context.Background())

			sub := &subject.Subject{}

			tc.configureContextAndSubject(t, mctx, sub)

			auth, err := newCELAuthorizer(tc.id, conf)
			require.NoError(t, err)

			// WHEN
			err = auth.Execute(mctx, sub)

			// THEN
			tc.assert(t, err)

			mctx.AssertExpectations(t)
		})
	}
}
