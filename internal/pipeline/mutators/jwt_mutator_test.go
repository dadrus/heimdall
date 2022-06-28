package mutators

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/heimdall"
	heimdallmocks "github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/dadrus/heimdall/internal/x"
)

func TestCreateJWTMutator(t *testing.T) {
	t.Parallel()

	const expectedTTL = 5 * time.Second

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, mut *jwtMutator)
	}{
		{
			uc: "without config",
			assert: func(t *testing.T, err error, mut *jwtMutator) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, mut)
				assert.Equal(t, defaultJWTTTL, mut.ttl)
				assert.Nil(t, mut.claims)
			},
		},
		{
			uc:     "with empty config",
			config: []byte(``),
			assert: func(t *testing.T, err error, mut *jwtMutator) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, mut)
				assert.Equal(t, defaultJWTTTL, mut.ttl)
				assert.Nil(t, mut.claims)
			},
		},
		{
			uc:     "with ttl only",
			config: []byte(`ttl: 5s`),
			assert: func(t *testing.T, err error, mut *jwtMutator) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, mut)
				assert.Equal(t, expectedTTL, mut.ttl)
				assert.Nil(t, mut.claims)
			},
		},
		{
			uc:     "with too short ttl",
			config: []byte(`ttl: 5ms`),
			assert: func(t *testing.T, err error, mut *jwtMutator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "less than one second")
			},
		},
		{
			uc: "with claims only",
			config: []byte(`
claims: 
  '{ "sub": {{ quote .Subject.ID }} }'
`),
			assert: func(t *testing.T, err error, mut *jwtMutator) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, mut)
				assert.Equal(t, defaultJWTTTL, mut.ttl)
				require.NotNil(t, mut.claims)
				val, err := mut.claims.Render(nil, &subject.Subject{ID: "bar"})
				require.NoError(t, err)
				assert.Equal(t, `{ "sub": "bar" }`, val)
			},
		},
		{
			uc: "with claims and ttl",
			config: []byte(`
ttl: 5s
claims: 
  '{ "sub": {{ quote .Subject.ID }} }'
`),
			assert: func(t *testing.T, err error, mut *jwtMutator) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, mut)
				assert.Equal(t, expectedTTL, mut.ttl)
				require.NotNil(t, mut.claims)
				val, err := mut.claims.Render(nil, &subject.Subject{ID: "bar"})
				require.NoError(t, err)
				assert.Equal(t, `{ "sub": "bar" }`, val)
			},
		},
		{
			uc: "with unknown entries in configuration",
			config: []byte(`
ttl: 5s
foo: bar"
`),
			assert: func(t *testing.T, err error, mut *jwtMutator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			mutator, err := newJWTMutator(conf)

			// THEN
			tc.assert(t, err, mutator)
		})
	}
}

func TestCreateJWTMutatorFromPrototype(t *testing.T) {
	t.Parallel()

	const (
		expectedTTL = 5 * time.Second
	)

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, prototype *jwtMutator, configured *jwtMutator)
	}{
		{
			uc: "no new configuration provided",
			assert: func(t *testing.T, err error, prototype *jwtMutator, configured *jwtMutator) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc:     "empty configuration provided",
			config: []byte(``),
			assert: func(t *testing.T, err error, prototype *jwtMutator, configured *jwtMutator) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc:     "configuration with ttl only provided",
			config: []byte(`ttl: 5s`),
			assert: func(t *testing.T, err error, prototype *jwtMutator, configured *jwtMutator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.claims, configured.claims)
				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, expectedTTL, configured.ttl)
			},
		},
		{
			uc:     "configuration with too short ttl",
			config: []byte(`ttl: 5ms`),
			assert: func(t *testing.T, err error, prototype *jwtMutator, configured *jwtMutator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "less than one second")
			},
		},
		{
			uc: "configuration with claims only provided",
			config: []byte(`
claims:
  '{ "sub": {{ quote .Subject.ID }} }'
`),
			assert: func(t *testing.T, err error, prototype *jwtMutator, configured *jwtMutator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.NotEqual(t, prototype.claims, configured.claims)
				require.NotNil(t, configured.claims)
				val, err := configured.claims.Render(nil, &subject.Subject{ID: "bar"})
				require.NoError(t, err)
				assert.Equal(t, `{ "sub": "bar" }`, val)
			},
		},
		{
			uc: "configuration with both ttl and claims provided",
			config: []byte(`
ttl: 5s
claims:
  '{ "sub": {{ quote .Subject.ID }} }'
`),
			assert: func(t *testing.T, err error, prototype *jwtMutator, configured *jwtMutator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, expectedTTL, configured.ttl)
				assert.NotEqual(t, prototype.claims, configured.claims)
				require.NotNil(t, configured.claims)
				val, err := configured.claims.Render(nil, &subject.Subject{ID: "bar"})
				require.NoError(t, err)
				assert.Equal(t, `{ "sub": "bar" }`, val)
			},
		},
		{
			uc: "with unknown entries in configuration",
			config: []byte(`
ttl: 5s
foo: bar
`),
			assert: func(t *testing.T, err error, prototype *jwtMutator, configured *jwtMutator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newJWTMutator(nil)
			require.NoError(t, err)

			// WHEN
			mutator, err := prototype.WithConfig(conf)

			// THEN
			var (
				jwtMut *jwtMutator
				ok     bool
			)

			if err == nil {
				jwtMut, ok = mutator.(*jwtMutator)
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, jwtMut)
		})
	}
}

func TestJWTMutatorExecute(t *testing.T) {
	t.Parallel()

	const configuredTTL = 1 * time.Minute

	for _, tc := range []struct {
		uc             string
		config         []byte
		subject        *subject.Subject
		configureMocks func(t *testing.T,
			ctx *heimdallmocks.MockContext,
			signer *heimdallmocks.MockJWTSigner,
			cch *mocks.MockCache,
			sub *subject.Subject)
		assert func(t *testing.T, err error)
	}{
		{
			uc: "with 'nil' subject",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "'nil' subject")
			},
		},
		{
			uc:      "with used prefilled cache",
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.MockContext, signer *heimdallmocks.MockJWTSigner,
				cch *mocks.MockCache, sub *subject.Subject,
			) {
				t.Helper()

				signer.On("Hash").Return("foobar")

				ctx.On("Signer").Return(signer)
				ctx.On("AddResponseHeader", "Authorization", "Bearer TestToken")

				mut := jwtMutator{ttl: defaultJWTTTL}

				cacheKey, err := mut.calculateCacheKey(sub, signer)
				require.NoError(t, err)

				cch.On("Get", cacheKey).Return("TestToken")
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:      "with bad prefilled cache and without custom claims",
			config:  []byte(`ttl: 1m`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.MockContext, signer *heimdallmocks.MockJWTSigner,
				cch *mocks.MockCache, sub *subject.Subject,
			) {
				t.Helper()

				signer.On("Hash").Return("foobar")
				signer.On("Sign", sub.ID, configuredTTL, map[string]any{}).
					Return("barfoo", nil)

				ctx.On("Signer").Return(signer)
				ctx.On("AddResponseHeader", "Authorization", "Bearer barfoo")

				mut := jwtMutator{ttl: configuredTTL}

				cacheKey, err := mut.calculateCacheKey(sub, signer)
				require.NoError(t, err)

				cch.On("Get", cacheKey).Return(time.Second)
				cch.On("Delete", cacheKey)
				cch.On("Set", cacheKey, "barfoo", configuredTTL-defaultCacheLeeway)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:      "with no cache hit and without custom claims",
			config:  []byte(`ttl: 1m`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.MockContext, signer *heimdallmocks.MockJWTSigner,
				cch *mocks.MockCache, sub *subject.Subject,
			) {
				t.Helper()

				signer.On("Hash").Return("foobar")
				signer.On("Sign", sub.ID, configuredTTL, map[string]any{}).
					Return("barfoo", nil)

				ctx.On("Signer").Return(signer)
				ctx.On("AddResponseHeader", "Authorization", "Bearer barfoo")

				cch.On("Get", mock.Anything).Return(nil)
				cch.On("Set", mock.Anything, "barfoo", configuredTTL-defaultCacheLeeway)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc: "with no cache hit and with custom claims",
			config: []byte(`
claims: '{
  {{ $val := .Subject.Attributes.baz }}
  "sub_id": {{ quote .Subject.ID }}, 
  {{ quote $val }}: "baz"
}'`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.MockContext, signer *heimdallmocks.MockJWTSigner,
				cch *mocks.MockCache, sub *subject.Subject,
			) {
				t.Helper()

				signer.On("Hash").Return("foobar")
				signer.On("Sign", sub.ID, defaultJWTTTL, map[string]any{
					"sub_id": "foo",
					"bar":    "baz",
				}).Return("barfoo", nil)

				ctx.On("Signer").Return(signer)
				ctx.On("AddResponseHeader", "Authorization", "Bearer barfoo")

				cch.On("Get", mock.Anything).Return(nil)
				cch.On("Set", mock.Anything, "barfoo", defaultJWTTTL-defaultCacheLeeway)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:      "with custom claims template, which does not result in a JSON object",
			config:  []byte(`claims: "foo: bar"`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.MockContext, signer *heimdallmocks.MockJWTSigner,
				cch *mocks.MockCache, sub *subject.Subject,
			) {
				t.Helper()

				signer.On("Hash").Return("foobar")

				ctx.On("Signer").Return(signer)
				cch.On("Get", mock.Anything).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to unmarshal claims")
			},
		},
		{
			uc:      "with custom claims template, which fails during rendering",
			config:  []byte(`claims: "{{ .foobar }}"`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.MockContext, signer *heimdallmocks.MockJWTSigner,
				cch *mocks.MockCache, sub *subject.Subject,
			) {
				t.Helper()

				signer.On("Hash").Return("foobar")

				ctx.On("Signer").Return(signer)
				cch.On("Get", mock.Anything).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to render")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, _ *heimdallmocks.MockContext, _ *heimdallmocks.MockJWTSigner,
					_ *mocks.MockCache, _ *subject.Subject,
				) {
					t.Helper()
				})

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			cch := &mocks.MockCache{}
			mctx := &heimdallmocks.MockContext{}
			signer := &heimdallmocks.MockJWTSigner{}

			mctx.On("AppContext").Return(cache.WithContext(context.Background(), cch))
			configureMocks(t, mctx, signer, cch, tc.subject)

			mutator, err := newJWTMutator(conf)
			require.NoError(t, err)

			// WHEN
			err = mutator.Execute(mctx, tc.subject)

			// THEN
			tc.assert(t, err)

			mctx.AssertExpectations(t)
			cch.AssertExpectations(t)
			signer.AssertExpectations(t)
		})
	}
}
