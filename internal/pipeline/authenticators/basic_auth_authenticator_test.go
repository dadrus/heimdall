package authenticators

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/testsupport"
)

func TestCreateBasicAuthAuthenticator(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, auth *basicAuthAuthenticator)
	}{
		{
			uc: "valid configuration",
			config: []byte(`
user_id: foo
password: bar`),
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				md := sha256.New()
				md.Write([]byte("foo"))
				userID := hex.EncodeToString(md.Sum(nil))

				md.Reset()
				md.Write([]byte("bar"))
				password := hex.EncodeToString(md.Sum(nil))

				assert.Equal(t, userID, auth.UserID)
				assert.Equal(t, password, auth.Password)
			},
		},
		{
			uc: "without user_id",
			config: []byte(`
password: bar`),
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)

				assert.Nil(t, auth)
			},
		},
		{
			uc: "without password",
			config: []byte(`
user_id: foo`),
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)

				assert.Nil(t, auth)
			},
		},
		{
			uc: "with unexpected config attribute",
			config: []byte(`
user_id: foo
password: bar
foo: bar`),
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)

				assert.Nil(t, auth)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			auth, err := newBasicAuthAuthenticator(conf)

			// THEN
			tc.assert(t, err, auth)
		})
	}
}

func TestCreateBasicAuthAuthenticatorFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *basicAuthAuthenticator, configured *basicAuthAuthenticator)
	}{
		{
			uc: "no new configuration for the configured authenticator",
			prototypeConfig: []byte(`
user_id: foo
password: bar`),
			assert: func(t *testing.T, err error, prototype *basicAuthAuthenticator, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc: "password differs",
			prototypeConfig: []byte(`
user_id: foo
password: bar`),
			config: []byte(`
user_id: foo
password: baz`),
			assert: func(t *testing.T, err error, prototype *basicAuthAuthenticator, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)

				assert.Equal(t, prototype.UserID, configured.UserID)
				assert.NotEqual(t, prototype.Password, configured.Password)
			},
		},
		{
			uc: "no user_id provided",
			prototypeConfig: []byte(`
user_id: foo
password: bar`),
			config: []byte(`
password: baz`),
			assert: func(t *testing.T, err error, prototype *basicAuthAuthenticator, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)

				assert.Equal(t, prototype.UserID, configured.UserID)
				assert.NotEqual(t, prototype.Password, configured.Password)
			},
		},
		{
			uc: "no password provided",
			prototypeConfig: []byte(`
user_id: foo
password: bar`),
			config: []byte(`
user_id: baz`),
			assert: func(t *testing.T, err error, prototype *basicAuthAuthenticator, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)

				assert.NotEqual(t, prototype.UserID, configured.UserID)
				assert.Equal(t, prototype.Password, configured.Password)
			},
		},
		{
			uc: "user_id differs",
			prototypeConfig: []byte(`
user_id: foo
password: bar`),
			config: []byte(`
user_id: baz
password: bar`),
			assert: func(t *testing.T, err error, prototype *basicAuthAuthenticator, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)

				assert.NotEqual(t, prototype.UserID, configured.UserID)
				assert.Equal(t, prototype.Password, configured.Password)
			},
		},
		{
			uc: "user_id and password differs",
			prototypeConfig: []byte(`
user_id: foo
password: bar`),
			config: []byte(`
user_id: baz
password: baz`),
			assert: func(t *testing.T, err error, prototype *basicAuthAuthenticator, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)

				assert.NotEqual(t, prototype.UserID, configured.UserID)
				assert.NotEqual(t, prototype.Password, configured.Password)

				md := sha256.New()
				md.Write([]byte("baz"))
				value := hex.EncodeToString(md.Sum(nil))

				assert.Equal(t, value, configured.UserID)
				assert.Equal(t, value, configured.Password)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newBasicAuthAuthenticator(pc)
			require.NoError(t, err)

			// WHEN
			auth, err := prototype.WithConfig(conf)

			// THEN
			baa, ok := auth.(*basicAuthAuthenticator)
			require.True(t, ok)

			tc.assert(t, err, prototype, baa)
		})
	}
}

func TestBasicAuthAuthenticatorExecute(t *testing.T) {
	t.Parallel()

	conf, err := testsupport.DecodeTestConfig([]byte(`
user_id: foo
password: bar`))
	require.NoError(t, err)

	for _, tc := range []struct {
		uc               string
		configureContext func(t *testing.T, ctx *mocks.MockContext)
		assert           func(t *testing.T, err error, sub *subject.Subject)
	}{
		{
			uc: "no authorization header",
			configureContext: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "Authorization").Return("")
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "no Authorization header")

				assert.Nil(t, sub)
			},
		},
		{
			uc: "malformed scheme",
			configureContext: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "Authorization").Return("foo bar baz")
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "unexpected value")

				assert.Nil(t, sub)
			},
		},
		{
			uc: "unexpected authentication scheme",
			configureContext: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "Authorization").Return("foo bar")
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "unexpected authentication scheme")

				assert.Nil(t, sub)
			},
		},
		{
			uc: "base64 decoding error",
			configureContext: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "Authorization").Return("Basic bar")
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.NotErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "failed to decode")

				assert.Nil(t, sub)
			},
		},
		{
			uc: "malformed encoding",
			configureContext: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "Authorization").
					Return("Basic " + base64.StdEncoding.EncodeToString([]byte("foo|bar")))
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.NotErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "malformed user-id - password")

				assert.Nil(t, sub)
			},
		},
		{
			uc: "invalid user id",
			configureContext: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "Authorization").
					Return("Basic " + base64.StdEncoding.EncodeToString([]byte("baz:bar")))
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.NotErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "invalid user credentials")

				assert.Nil(t, sub)
			},
		},
		{
			uc: "invalid password",
			configureContext: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "Authorization").
					Return("Basic " + base64.StdEncoding.EncodeToString([]byte("foo:baz")))
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.NotErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "invalid user credentials")

				assert.Nil(t, sub)
			},
		},
		{
			uc: "valid credentials",
			configureContext: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "Authorization").
					Return("Basic " + base64.StdEncoding.EncodeToString([]byte("foo:bar")))
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, sub)

				assert.Equal(t, sub.ID, "foo")
				assert.NotNil(t, sub.Attributes)
			},
		},
	} {
		// GIVEN
		auth, err := newBasicAuthAuthenticator(conf)
		require.NoError(t, err)

		ctx := &mocks.MockContext{}
		ctx.On("AppContext").Return(context.Background())
		tc.configureContext(t, ctx)

		// WHEN
		sub, err := auth.Execute(ctx)

		// THEN
		tc.assert(t, err, sub)
		ctx.AssertExpectations(t)
	}
}
