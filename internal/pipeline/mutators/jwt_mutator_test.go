package mutators

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/heimdall"
	heimdallmocks "github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/pipeline/template"
	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/dadrus/heimdall/internal/x"
)

func TestCreateJWTMutator(t *testing.T) {
	t.Parallel()

	const (
		expectedTTL      = 5 * time.Second
		expectedTemplate = template.Template("{{ foobar }}")
	)

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
			uc:     "with claims only",
			config: []byte(`claims: "{{ foobar }}"`),
			assert: func(t *testing.T, err error, mut *jwtMutator) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, mut)
				assert.Equal(t, defaultJWTTTL, mut.ttl)
				assert.Equal(t, expectedTemplate, *mut.claims)
			},
		},
		{
			uc: "with claims and ttl",
			config: []byte(`
ttl: 5s
claims: "{{ foobar }}"
`),
			assert: func(t *testing.T, err error, mut *jwtMutator) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, mut)
				assert.Equal(t, expectedTTL, mut.ttl)
				assert.Equal(t, expectedTemplate, *mut.claims)
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
		expectedTTL      = 5 * time.Second
		expectedTemplate = template.Template("{{ foobar }}")
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
			uc:     "configuration with claims only provided",
			config: []byte(`claims: "{{ foobar }}"`),
			assert: func(t *testing.T, err error, prototype *jwtMutator, configured *jwtMutator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.NotEqual(t, prototype.claims, configured.claims)
				assert.Equal(t, expectedTemplate, *configured.claims)
			},
		},
		{
			uc: "configuration with both ttl and claims provided",
			config: []byte(`
ttl: 5s
claims: "{{ foobar }}"
`),
			assert: func(t *testing.T, err error, prototype *jwtMutator, configured *jwtMutator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, expectedTTL, configured.ttl)
				assert.NotEqual(t, prototype.claims, configured.claims)
				assert.Equal(t, expectedTemplate, *configured.claims)
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

// nolint: maintidx
func TestJWTMutatorExecute(t *testing.T) {
	t.Parallel()

	const (
		rsa2048       = 2048
		configuredTTL = 1 * time.Minute
	)

	issuerName := "testIssuer"
	keyID := "testKeyID"
	sigAlg := string(jose.RS256)

	privateKey, err := rsa.GenerateKey(rand.Reader, rsa2048)
	require.NoError(t, err)

	signer := &MockJWTSigner{}
	signer.On("Name").Return(issuerName)
	signer.On("KeyID").Return(keyID)
	signer.On("Algorithm").Return(sigAlg)
	signer.On("Key").Return(privateKey)

	validateGeneratedJWT := func(
		sub *subject.Subject,
		ttl time.Duration,
		customClaims map[string]any,
	) func(jwt string) bool {
		return func(rawJWT string) bool {
			t.Helper()

			const jwtDotCount = 2

			require.Equal(t, strings.Count(rawJWT, "."), jwtDotCount)

			token, err := jwt.ParseSigned(rawJWT)
			require.NoError(t, err)

			var claims map[string]any

			assert.Len(t, token.Headers, 1)
			assert.Equal(t, keyID, token.Headers[0].KeyID)
			assert.Equal(t, sigAlg, token.Headers[0].Algorithm)

			err = token.Claims(privateKey.Public(), &claims)
			require.NoError(t, err)

			assert.Contains(t, claims, "exp")
			assert.Contains(t, claims, "jti")
			assert.Contains(t, claims, "iat")
			assert.Contains(t, claims, "iss")
			assert.Contains(t, claims, "nbf")
			assert.Contains(t, claims, "sub")

			assert.Equal(t, sub.ID, claims["sub"])
			assert.Equal(t, issuerName, claims["iss"])

			exp, ok := claims["exp"].(float64)
			require.True(t, ok)
			nbf, ok := claims["nbf"].(float64)
			require.True(t, ok)
			iat, ok := claims["iat"].(float64)
			require.True(t, ok)

			now := time.Now().Unix()
			assert.True(t, float64(now) >= iat)

			assert.Equal(t, iat, nbf)
			assert.Equal(t, exp-ttl.Seconds(), nbf)

			for k, v := range customClaims {
				assert.Contains(t, claims, k)
				assert.Equal(t, v, claims[k])
			}

			return true
		}
	}

	for _, tc := range []struct {
		uc               string
		config           []byte
		subject          *subject.Subject
		configureContext func(t *testing.T, ctx *heimdallmocks.MockContext)
		configureCache   func(t *testing.T, cch *mocks.MockCache, sub *subject.Subject)
		assert           func(t *testing.T, err error)
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
			configureCache: func(t *testing.T, cch *mocks.MockCache, sub *subject.Subject) {
				t.Helper()

				mut := jwtMutator{ttl: defaultJWTTTL}

				cacheKey, err := mut.calculateCacheKey(sub, signer)
				require.NoError(t, err)

				cch.On("Get", cacheKey).Return("TestToken")
			},
			configureContext: func(t *testing.T, ctx *heimdallmocks.MockContext) {
				t.Helper()

				ctx.On("Signer").Return(signer)
				ctx.On("AddResponseHeader", "Authorization", "Bearer TestToken")
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:      "with bad prefilled cache",
			config:  []byte(`ttl: 1m`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureCache: func(t *testing.T, cch *mocks.MockCache, sub *subject.Subject) {
				t.Helper()

				mut := jwtMutator{ttl: configuredTTL}

				cacheKey, err := mut.calculateCacheKey(sub, signer)
				require.NoError(t, err)

				cch.On("Get", cacheKey).Return(time.Second)
				cch.On("Delete", cacheKey)
				cch.On("Set", cacheKey,
					mock.MatchedBy(validateGeneratedJWT(sub, configuredTTL, nil)),
					configuredTTL-defaultCacheLeeway)
			},
			configureContext: func(t *testing.T, ctx *heimdallmocks.MockContext) {
				t.Helper()

				ctx.On("Signer").Return(signer)
				ctx.On("AddResponseHeader", "Authorization",
					mock.MatchedBy(func(val string) bool { return strings.HasPrefix(val, "Bearer ") }))
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
			configureCache: func(t *testing.T, cch *mocks.MockCache, sub *subject.Subject) {
				t.Helper()

				cch.On("Get", mock.Anything).Return(nil)
				cch.On("Set", mock.Anything,
					mock.MatchedBy(validateGeneratedJWT(sub, configuredTTL, nil)),
					configuredTTL-defaultCacheLeeway)
			},
			configureContext: func(t *testing.T, ctx *heimdallmocks.MockContext) {
				t.Helper()

				ctx.On("Signer").Return(signer)
				ctx.On("AddResponseHeader", "Authorization",
					mock.MatchedBy(func(val string) bool { return strings.HasPrefix(val, "Bearer ") }))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc: "with no cache hit and with custom claims",
			config: []byte(`
claims: "{
  {{ $val := .Attributes.baz }}
  \"sub_id\": {{ quote .ID }}, 
  {{ quote $val }}: \"baz\"
}"`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureCache: func(t *testing.T, cch *mocks.MockCache, sub *subject.Subject) {
				t.Helper()

				cch.On("Get", mock.Anything).Return(nil)
				cch.On("Set", mock.Anything,
					mock.MatchedBy(validateGeneratedJWT(sub, defaultJWTTTL, map[string]any{"sub_id": "foo", "bar": "baz"})),
					defaultJWTTTL-defaultCacheLeeway)
			},
			configureContext: func(t *testing.T, ctx *heimdallmocks.MockContext) {
				t.Helper()

				ctx.On("Signer").Return(signer)
				ctx.On("AddResponseHeader", "Authorization",
					mock.MatchedBy(func(val string) bool { return strings.HasPrefix(val, "Bearer ") }))
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
			configureCache: func(t *testing.T, cch *mocks.MockCache, sub *subject.Subject) {
				t.Helper()

				cch.On("Get", mock.Anything).Return(nil)
			},
			configureContext: func(t *testing.T, ctx *heimdallmocks.MockContext) {
				t.Helper()

				ctx.On("Signer").Return(signer)
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
			configureCache: func(t *testing.T, cch *mocks.MockCache, sub *subject.Subject) {
				t.Helper()

				cch.On("Get", mock.Anything).Return(nil)
			},
			configureContext: func(t *testing.T, ctx *heimdallmocks.MockContext) {
				t.Helper()

				ctx.On("Signer").Return(signer)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to render")
			},
		},
		{
			uc:      "with bad signer configuration",
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureCache: func(t *testing.T, cch *mocks.MockCache, sub *subject.Subject) {
				t.Helper()

				cch.On("Get", mock.Anything).Return(nil)
			},
			configureContext: func(t *testing.T, ctx *heimdallmocks.MockContext) {
				t.Helper()

				badSigner := &MockJWTSigner{}
				badSigner.On("Name").Return(issuerName)
				badSigner.On("KeyID").Return(keyID)
				badSigner.On("Algorithm").Return("FooBar")
				badSigner.On("Key").Return(privateKey)

				ctx.On("Signer").Return(badSigner)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "JWT signer")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureCache := x.IfThenElse(tc.configureCache != nil,
				tc.configureCache,
				func(_ *testing.T, _ *mocks.MockCache, _ *subject.Subject) {})

			configureContext := x.IfThenElse(tc.configureContext != nil,
				tc.configureContext,
				func(_ *testing.T, _ *heimdallmocks.MockContext) {})

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			cch := &mocks.MockCache{}
			configureCache(t, cch, tc.subject)

			mctx := &heimdallmocks.MockContext{}
			mctx.On("AppContext").Return(cache.WithContext(context.Background(), cch))
			configureContext(t, mctx)

			mutator, err := newJWTMutator(conf)
			require.NoError(t, err)

			// WHEN
			err = mutator.Execute(mctx, tc.subject)

			// THEN
			tc.assert(t, err)

			mctx.AssertExpectations(t)
			cch.AssertExpectations(t)
		})
	}
}
