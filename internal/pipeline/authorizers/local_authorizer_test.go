package authorizers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/pipeline/testsupport"
)

func TestCreateLocalAuthorizer(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, auth *localAuthorizer)
	}{
		{
			uc: "without configuration",
			assert: func(t *testing.T, err error, auth *localAuthorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no script provided")
			},
		},
		{
			uc:     "without script",
			config: []byte(``),
			assert: func(t *testing.T, err error, auth *localAuthorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no script provided")
			},
		},
		{
			uc:     "with malformed script",
			config: []byte(`script: "return foo"`),
			assert: func(t *testing.T, err error, auth *localAuthorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to compile")
			},
		},
		{
			uc: "with unsupported attributes",
			config: []byte(`
script: "return foo"
foo: bar
`),
			assert: func(t *testing.T, err error, auth *localAuthorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
		{
			uc:     "with valid script",
			config: []byte(`script: "console.log('Executing JS Code')"`),
			assert: func(t *testing.T, err error, auth *localAuthorizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, auth.p)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			a, err := newLocalAuthorizer(conf)

			// THEN
			tc.assert(t, err, a)
		})
	}
}

func TestCreateLocalAuthorizerFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *localAuthorizer, configured *localAuthorizer)
	}{
		{
			uc:              "no new configuration provided",
			prototypeConfig: []byte(`script: "console.log('Executing JS Code')"`),
			assert: func(t *testing.T, err error, prototype *localAuthorizer, configured *localAuthorizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc:              "configuration without script provided",
			prototypeConfig: []byte(`script: "console.log('Executing JS Code')"`),
			config:          []byte(``),
			assert: func(t *testing.T, err error, prototype *localAuthorizer, configured *localAuthorizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc:              "new script provided",
			prototypeConfig: []byte(`script: "console.log('Executing JS Code')"`),
			config:          []byte(`script: "console.log('New JS script')"`),
			assert: func(t *testing.T, err error, prototype *localAuthorizer, configured *localAuthorizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				require.NotNil(t, configured)
				assert.NotNil(t, configured.p)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newLocalAuthorizer(pc)
			require.NoError(t, err)

			// WHEN
			auth, err := prototype.WithConfig(conf)

			// THEN
			jwta, ok := auth.(*localAuthorizer)
			require.True(t, ok)

			tc.assert(t, err, prototype, jwta)
		})
	}
}

func TestLocalAuthorizerExecute(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc                         string
		config                     []byte
		configureContextAndSubject func(t *testing.T, ctx *testsupport.MockContext, sub *subject.Subject)
		assert                     func(t *testing.T, err error)
	}{
		{
			uc:     "denied by script",
			config: []byte(`script: "throw('denied by script')"`),
			configureContextAndSubject: func(t *testing.T, ctx *testsupport.MockContext, sub *subject.Subject) {
				// nothing is required here
				t.Helper()
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthorization)
				assert.Contains(t, err.Error(), "denied by script")
			},
		},
		{
			uc:     "script can use subject and context",
			config: []byte(`script: "throw(heimdall.ctx.RequestHeader(heimdall.subject.ID))"`),
			configureContextAndSubject: func(t *testing.T, ctx *testsupport.MockContext, sub *subject.Subject) {
				t.Helper()

				sub.ID = "foobar"
				ctx.On("RequestHeader", "foobar").Return("barfoo")
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthorization)
				assert.Contains(t, err.Error(), "barfoo")
			},
		},
		{
			uc:     "allowed by script",
			config: []byte(`script: "true"`),
			configureContextAndSubject: func(t *testing.T, ctx *testsupport.MockContext, sub *subject.Subject) {
				// nothing is required here
				t.Helper()
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

			mctx := &testsupport.MockContext{}
			mctx.On("AppContext").Return(context.Background())

			sub := &subject.Subject{}

			tc.configureContextAndSubject(t, mctx, sub)

			auth, err := newLocalAuthorizer(conf)
			require.NoError(t, err)

			// WHEN
			err = auth.Execute(mctx, sub)

			// THEN
			tc.assert(t, err)

			mctx.AssertExpectations(t)
		})
	}
}
