package authenticators

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/heimdall"
	heimdallmocks "github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/pipeline/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/oauth2"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/dadrus/heimdall/internal/x"
)

func TestCreateJwtAuthenticator(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, a *jwtAuthenticator)
	}{
		{
			uc: "with unsupported fields",
			config: []byte(`
jwt_from:
  - header: foo-header
foo: bar
`),
			assert: func(t *testing.T, err error, a *jwtAuthenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
		{
			uc: "missing jwks url config",
			config: []byte(`
jwt_from:
  - header: foo-header
assertions:
  issuers:
    - foobar
session:
  subject_id_from: some_template`),
			assert: func(t *testing.T, err error, a *jwtAuthenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "endpoint configuration")
			},
		},
		{
			uc: "missing trusted_issuers config",
			config: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  audience:
    - foobar
session:
  subject_id_from: some_template`),
			assert: func(t *testing.T, err error, a *jwtAuthenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no trusted issuers")
			},
		},
		{
			uc: "valid configuration with defaults, without cache",
			config: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  issuers:
    - foobar`),
			assert: func(t *testing.T, err error, auth *jwtAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				// endpoint settings
				assert.Equal(t, "http://test.com", auth.e.URL)
				assert.Equal(t, "GET", auth.e.Method)
				assert.Equal(t, 1, len(auth.e.Headers))
				assert.Contains(t, auth.e.Headers, "Accept-Type")
				assert.Equal(t, auth.e.Headers["Accept-Type"], "application/json")

				// token extractor settings
				assert.IsType(t, extractors.CompositeExtractStrategy{}, auth.ads)
				assert.Len(t, auth.ads, 2)
				assert.Contains(t, auth.ads, extractors.HeaderValueExtractStrategy{Name: "Authorization", Prefix: "Bearer"})
				assert.Contains(t, auth.ads, extractors.QueryParameterExtractStrategy{Name: "access_token"})

				// assertions settings
				assert.NoError(t, auth.a.ScopesMatcher.Match([]string{}))
				assert.Empty(t, auth.a.TargetAudiences)
				assert.Len(t, auth.a.TrustedIssuers, 1)
				assert.Contains(t, auth.a.TrustedIssuers, "foobar")
				assert.Len(t, auth.a.AllowedAlgorithms, 6)

				assert.ElementsMatch(t, auth.a.AllowedAlgorithms, []string{
					string(jose.ES256), string(jose.ES384), string(jose.ES512),
					string(jose.PS256), string(jose.PS384), string(jose.PS512),
				})
				assert.Equal(t, time.Duration(0), auth.a.ValidityLeeway)

				// session settings
				sess, ok := auth.sf.(*Session)
				require.True(t, ok)
				assert.Equal(t, "sub", sess.SubjectIDFrom)
				assert.Empty(t, sess.SubjectAttributesFrom)

				// cache sessiong
				assert.Equal(t, defaultTTL, auth.ttl)
			},
		},
		{
			uc: "valid configuration with defaults and cache",
			config: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  issuers:
    - foobar
cache_ttl: 5s`),
			assert: func(t *testing.T, err error, auth *jwtAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				// endpoint settings
				assert.Equal(t, "http://test.com", auth.e.URL)
				assert.Equal(t, "GET", auth.e.Method)
				assert.Equal(t, 1, len(auth.e.Headers))
				assert.Contains(t, auth.e.Headers, "Accept-Type")
				assert.Equal(t, auth.e.Headers["Accept-Type"], "application/json")

				// token extractor settings
				assert.IsType(t, extractors.CompositeExtractStrategy{}, auth.ads)
				assert.Len(t, auth.ads, 2)
				assert.Contains(t, auth.ads, extractors.HeaderValueExtractStrategy{Name: "Authorization", Prefix: "Bearer"})
				assert.Contains(t, auth.ads, extractors.QueryParameterExtractStrategy{Name: "access_token"})

				// assertions settings
				assert.NoError(t, auth.a.ScopesMatcher.Match([]string{}))
				assert.Empty(t, auth.a.TargetAudiences)
				assert.Len(t, auth.a.TrustedIssuers, 1)
				assert.Contains(t, auth.a.TrustedIssuers, "foobar")
				assert.Len(t, auth.a.AllowedAlgorithms, 6)

				assert.ElementsMatch(t, auth.a.AllowedAlgorithms, []string{
					string(jose.ES256), string(jose.ES384), string(jose.ES512),
					string(jose.PS256), string(jose.PS384), string(jose.PS512),
				})
				assert.Equal(t, time.Duration(0), auth.a.ValidityLeeway)

				// session settings
				sess, ok := auth.sf.(*Session)
				require.True(t, ok)
				assert.Equal(t, "sub", sess.SubjectIDFrom)
				assert.Empty(t, sess.SubjectAttributesFrom)

				// cache sessiong
				assert.NotNil(t, auth.ttl)
				assert.Equal(t, 5*time.Second, auth.ttl)
			},
		},
		{
			uc: "valid configuration with overwrites, without cache",
			config: []byte(`
jwks_endpoint:
  url: http://test.com
  method: POST
  headers:
    Accept-Type: application/foobar
jwt_from:
  - header: foo-header
assertions:
  scopes:
    matching_strategy: wildcard
    values:
      - foo
  issuers:
    - foobar
  allowed_algorithms:
    - ES256
session:
  subject_id_from: some_claim`),
			assert: func(t *testing.T, err error, auth *jwtAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				// endpoint settings
				assert.Equal(t, "http://test.com", auth.e.URL)
				assert.Equal(t, "POST", auth.e.Method)
				assert.Equal(t, 1, len(auth.e.Headers))
				assert.Contains(t, auth.e.Headers, "Accept-Type")
				assert.Equal(t, auth.e.Headers["Accept-Type"], "application/foobar")

				// token extractor settings
				assert.IsType(t, extractors.CompositeExtractStrategy{}, auth.ads)
				assert.Len(t, auth.ads, 1)
				assert.Contains(t, auth.ads, &extractors.HeaderValueExtractStrategy{Name: "foo-header"})

				// assertions settings
				assert.NotNil(t, auth.a.ScopesMatcher)
				assert.NoError(t, auth.a.ScopesMatcher.Match([]string{"foo"}))
				assert.Empty(t, auth.a.TargetAudiences)
				assert.Len(t, auth.a.TrustedIssuers, 1)
				assert.Contains(t, auth.a.TrustedIssuers, "foobar")
				assert.Len(t, auth.a.AllowedAlgorithms, 1)

				assert.ElementsMatch(t, auth.a.AllowedAlgorithms, []string{string(jose.ES256)})
				assert.Equal(t, time.Duration(0), auth.a.ValidityLeeway)

				// session settings
				sess, ok := auth.sf.(*Session)
				require.True(t, ok)
				assert.Equal(t, "some_claim", sess.SubjectIDFrom)
				assert.Empty(t, sess.SubjectAttributesFrom)

				// cache sessiong
				assert.Equal(t, defaultTTL, auth.ttl)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			a, err := newJwtAuthenticator(conf)

			// THEN
			tc.assert(t, err, a)
		})
	}
}

func TestCreateJwtAuthenticatorFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *jwtAuthenticator, configured *jwtAuthenticator)
	}{
		{
			uc: "using empty target config",
			prototypeConfig: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  issuers:
    - foobar
cache_ttl: 5s`),
			assert: func(t *testing.T, err error, prototype *jwtAuthenticator, configured *jwtAuthenticator) {
				t.Helper()

				// THEN
				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc: "using unsupported fields",
			prototypeConfig: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  issuers:
    - foobar
cache_ttl: 5s`),
			config: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, prototype *jwtAuthenticator, configured *jwtAuthenticator) {
				t.Helper()

				// THEN
				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
		{
			uc: "prototype config without cache, target config with overwrites, but without cache",
			prototypeConfig: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  issuers:
    - foobar`),
			config: []byte(`
assertions:
  issuers:
    - barfoo
  allowed_algorithms:
    - ES512`),
			assert: func(t *testing.T, err error, prototype *jwtAuthenticator, configured *jwtAuthenticator) {
				t.Helper()

				// THEN
				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.a, configured.a)

				assert.NoError(t, configured.a.ScopesMatcher.Match([]string{}))
				assert.Empty(t, configured.a.TargetAudiences)
				assert.ElementsMatch(t, configured.a.TrustedIssuers, []string{"barfoo"})
				assert.ElementsMatch(t, configured.a.AllowedAlgorithms, []string{string(jose.ES512)})

				assert.Equal(t, prototype.ttl, configured.ttl)
			},
		},
		{
			uc: "prototype config without cache, config with overwrites incl cache",
			prototypeConfig: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  issuers:
    - foobar`),
			config: []byte(`
assertions:
  issuers:
    - barfoo
  allowed_algorithms:
    - ES512
cache_ttl: 5s`),
			assert: func(t *testing.T, err error, prototype *jwtAuthenticator, configured *jwtAuthenticator) {
				t.Helper()

				// THEN
				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.a, configured.a)

				assert.NoError(t, configured.a.ScopesMatcher.Match([]string{}))
				assert.Empty(t, configured.a.TargetAudiences)
				assert.ElementsMatch(t, configured.a.TrustedIssuers, []string{"barfoo"})
				assert.ElementsMatch(t, configured.a.AllowedAlgorithms, []string{string(jose.ES512)})

				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, 5*time.Second, configured.ttl)
			},
		},
		{
			uc: "prototype config with cache, config without",
			prototypeConfig: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  issuers:
    - foobar
cache_ttl: 5s`),
			config: []byte(`
assertions:
  issuers:
    - barfoo
  allowed_algorithms:
    - ES512`),
			assert: func(t *testing.T, err error, prototype *jwtAuthenticator, configured *jwtAuthenticator) {
				t.Helper()

				// THEN
				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.a, configured.a)

				assert.NoError(t, configured.a.ScopesMatcher.Match([]string{}))
				assert.Empty(t, configured.a.TargetAudiences)
				assert.ElementsMatch(t, configured.a.TrustedIssuers, []string{"barfoo"})
				assert.ElementsMatch(t, configured.a.AllowedAlgorithms, []string{string(jose.ES512)})

				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, 5*time.Second, configured.ttl)
			},
		},
		{
			uc: "prototype config with cache, target config with cache only",
			prototypeConfig: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  issuers:
    - foobar
cache_ttl: 5s`),
			config: []byte(`cache_ttl: 15s`),
			assert: func(t *testing.T, err error, prototype *jwtAuthenticator, configured *jwtAuthenticator) {
				t.Helper()

				// THEN
				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.Equal(t, prototype.a, configured.a)

				assert.Equal(t, 5*time.Second, prototype.ttl)
				assert.Equal(t, 15*time.Second, configured.ttl)
			},
		},
		{
			uc: "prototype without scopes configured, created authenticator configures them and merges other fields",
			prototypeConfig: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  issuers:
    - foobar
cache_ttl: 5s`),
			config: []byte(`
assertions:
  scopes:
    - foo
    - bar
`),
			assert: func(t *testing.T, err error, prototype *jwtAuthenticator, configured *jwtAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.a, configured.a)

				assert.Equal(t, prototype.a.TrustedIssuers, configured.a.TrustedIssuers)
				assert.Equal(t, prototype.a.TargetAudiences, configured.a.TargetAudiences)
				assert.Equal(t, prototype.a.AllowedAlgorithms, configured.a.AllowedAlgorithms)
				assert.Equal(t, prototype.a.ValidityLeeway, configured.a.ValidityLeeway)
				assert.NotEqual(t, prototype.a.ScopesMatcher, configured.a.ScopesMatcher)
				assert.Len(t, configured.a.ScopesMatcher, 2)
				assert.Contains(t, configured.a.ScopesMatcher, "foo")
				assert.Contains(t, configured.a.ScopesMatcher, "bar")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newJwtAuthenticator(pc)
			require.NoError(t, err)

			// WHEN
			auth, err := prototype.WithConfig(conf)

			// THEN
			var (
				jwta *jwtAuthenticator
				ok   bool
			)

			if err == nil {
				jwta, ok = auth.(*jwtAuthenticator)
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, jwta)
		})
	}
}

// nolint: maintidx
func TestJwtAuthenticatorExecute(t *testing.T) {
	t.Parallel()

	var (
		endpointCalled bool
		checkRequest   func(req *http.Request)

		responseHeaders     map[string]string
		responseContentType string
		responseContent     []byte
		responseCode        int
	)

	subjectID := "foo"
	issuer := "foobar"
	audience := "bar"
	keyID := "baz"
	uniqueJWKSRaw, uniqueJWTRaw := setup(t, keyID, subjectID, issuer, audience, true)
	notUniqueJWKSRaw, notUniqueJWTRaw := setup(t, keyID, subjectID, issuer, audience, false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpointCalled = true

		checkRequest(r)

		for hn, hv := range responseHeaders {
			w.Header().Set(hn, hv)
		}

		if responseContent != nil {
			w.Header().Set("Content-Type", responseContentType)
			w.Header().Set("Content-Length", strconv.Itoa(len(responseContent)))
			_, err := w.Write(responseContent)
			assert.NoError(t, err)
		}

		w.WriteHeader(responseCode)
	}))
	defer srv.Close()

	for _, tc := range []struct {
		uc             string
		authenticator  *jwtAuthenticator
		instructServer func(t *testing.T)
		configureMocks func(t *testing.T,
			ctx *heimdallmocks.MockContext,
			cch *mocks.MockCache,
			ads *mockAuthDataGetter,
			auth *jwtAuthenticator)
		assert func(t *testing.T, err error, sub *subject.Subject)
	}{
		{
			uc:            "with failing auth data source",
			authenticator: &jwtAuthenticator{},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				ads.On("GetAuthData", ctx).Return(nil, heimdall.ErrCommunicationTimeout)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "no JWT")
			},
		},
		{
			uc:            "with unsupported JWT format",
			authenticator: &jwtAuthenticator{},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: "foo.bar.baz.bam"}, nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "unsupported JWT format")
			},
		},
		{
			uc:            "with JWT parsing error",
			authenticator: &jwtAuthenticator{},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: "foo.bar.baz"}, nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "parse JWT")
			},
		},
		{
			uc: "with jwks endpoint communication error (dns)",
			authenticator: &jwtAuthenticator{
				e: endpoint.Endpoint{URL: "http://heimdall.test.local"},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: uniqueJWTRaw}, nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "jwks endpoint failed")
			},
		},
		{
			uc: "with unexpected response code from server",
			authenticator: &jwtAuthenticator{
				e: endpoint.Endpoint{URL: srv.URL},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: uniqueJWTRaw}, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				responseCode = http.StatusInternalServerError
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "unexpected response")
			},
		},
		{
			uc: "with jwks unmarshalling error",
			authenticator: &jwtAuthenticator{
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: uniqueJWTRaw}, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				responseCode = http.StatusOK
				responseContent = []byte(`Hello Foo`)
				responseContentType = "text/text"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
		{
			uc: "without unique key id",
			authenticator: &jwtAuthenticator{
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: notUniqueJWTRaw}, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				responseCode = http.StatusOK
				responseContent = notUniqueJWKSRaw
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "no (unique) key found")
			},
		},
		{
			uc: "with positive cache hit, but unsupported algorithm",
			authenticator: &jwtAuthenticator{
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
				a:   oauth2.Expectation{AllowedAlgorithms: []string{"foo"}},
				ttl: 10 * time.Second,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey(keyID)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(uniqueJWKSRaw, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(keyID)

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: uniqueJWTRaw}, nil)
				cch.On("Get", cacheKey).Return(&keys[0])
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "algorithm is not allowed")
			},
		},
		{
			uc: "with positive cache hit, but signature verification error",
			authenticator: &jwtAuthenticator{
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
				a:   oauth2.Expectation{AllowedAlgorithms: []string{"PS512"}},
				ttl: 10 * time.Second,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey(keyID)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(uniqueJWKSRaw, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(keyID)

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: notUniqueJWTRaw}, nil)
				cch.On("Get", cacheKey).Return(&keys[0])
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "JWT signature")
			},
		},
		{
			uc: "with positive cache hit, but claims verification error",
			authenticator: &jwtAuthenticator{
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
				a:   oauth2.Expectation{AllowedAlgorithms: []string{"PS512"}, TrustedIssuers: []string{"untrusted"}},
				ttl: 10 * time.Second,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey(keyID)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(uniqueJWKSRaw, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(keyID)

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: uniqueJWTRaw}, nil)
				cch.On("Get", cacheKey).Return(&keys[0])
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "assertion conditions")
			},
		},
		{
			uc: "with positive cache hit, but subject creation error",
			authenticator: &jwtAuthenticator{
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
				a: oauth2.Expectation{
					AllowedAlgorithms: []string{"PS512"},
					TrustedIssuers:    []string{issuer},
					ScopesMatcher:     oauth2.ExactScopeStrategyMatcher{},
				},
				sf:  &Session{SubjectIDFrom: "foobar"},
				ttl: 10 * time.Second,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey(keyID)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(uniqueJWKSRaw, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(keyID)

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: uniqueJWTRaw}, nil)
				cch.On("Get", cacheKey).Return(&keys[0])
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to extract subject")
			},
		},
		{
			uc: "successful with positive cache hit",
			authenticator: &jwtAuthenticator{
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
				a: oauth2.Expectation{
					AllowedAlgorithms: []string{"PS512"},
					TrustedIssuers:    []string{issuer},
					ScopesMatcher:     oauth2.ExactScopeStrategyMatcher{},
				},
				sf:  &Session{SubjectIDFrom: "sub"},
				ttl: 10 * time.Second,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey(keyID)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(uniqueJWKSRaw, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(keyID)

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: uniqueJWTRaw}, nil)
				cch.On("Get", cacheKey).Return(&keys[0])
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, subjectID, sub.ID)
				assert.Len(t, sub.Attributes, 8)
				assert.Len(t, sub.Attributes["aud"], 1)
				assert.Contains(t, sub.Attributes["aud"], audience)
				assert.Contains(t, sub.Attributes, "exp")
				assert.Contains(t, sub.Attributes, "iat")
				assert.Contains(t, sub.Attributes, "nbf")
				assert.Equal(t, issuer, sub.Attributes["iss"])
				assert.Contains(t, sub.Attributes["scp"], "foo")
				assert.Contains(t, sub.Attributes["scp"], "bar")
				assert.Equal(t, subjectID, sub.Attributes["sub"])
			},
		},
		{
			uc: "successful without cache hit",
			authenticator: &jwtAuthenticator{
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
				a: oauth2.Expectation{
					AllowedAlgorithms: []string{"PS512"},
					TrustedIssuers:    []string{issuer},
					ScopesMatcher:     oauth2.ExactScopeStrategyMatcher{},
				},
				sf:  &Session{SubjectIDFrom: "sub"},
				ttl: 10 * time.Second,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey(keyID)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(uniqueJWKSRaw, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(keyID)

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: uniqueJWTRaw}, nil)
				cch.On("Get", cacheKey).Return(nil)
				cch.On("Set", cacheKey, &keys[0], auth.ttl)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				responseCode = http.StatusOK
				responseContent = uniqueJWKSRaw
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, subjectID, sub.ID)
				assert.Len(t, sub.Attributes, 8)
				assert.Len(t, sub.Attributes["aud"], 1)
				assert.Contains(t, sub.Attributes["aud"], audience)
				assert.Contains(t, sub.Attributes, "exp")
				assert.Contains(t, sub.Attributes, "iat")
				assert.Contains(t, sub.Attributes, "nbf")
				assert.Equal(t, issuer, sub.Attributes["iss"])
				assert.Contains(t, sub.Attributes["scp"], "foo")
				assert.Contains(t, sub.Attributes["scp"], "bar")
				assert.Equal(t, subjectID, sub.Attributes["sub"])
			},
		},
		{
			uc: "successful without bad cache hit",
			authenticator: &jwtAuthenticator{
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
				a: oauth2.Expectation{
					AllowedAlgorithms: []string{"PS512"},
					TrustedIssuers:    []string{issuer},
					ScopesMatcher:     oauth2.ExactScopeStrategyMatcher{},
				},
				sf:  &Session{SubjectIDFrom: "sub"},
				ttl: 10 * time.Second,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey(keyID)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(uniqueJWKSRaw, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(keyID)

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: uniqueJWTRaw}, nil)
				cch.On("Get", cacheKey).Return("Hi Foo")
				cch.On("Delete", cacheKey)
				cch.On("Set", cacheKey, &keys[0], auth.ttl)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				responseCode = http.StatusOK
				responseContent = uniqueJWKSRaw
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, subjectID, sub.ID)
				assert.Len(t, sub.Attributes, 8)
				assert.Len(t, sub.Attributes["aud"], 1)
				assert.Contains(t, sub.Attributes["aud"], audience)
				assert.Contains(t, sub.Attributes, "exp")
				assert.Contains(t, sub.Attributes, "iat")
				assert.Contains(t, sub.Attributes, "nbf")
				assert.Equal(t, issuer, sub.Attributes["iss"])
				assert.Contains(t, sub.Attributes["scp"], "foo")
				assert.Contains(t, sub.Attributes["scp"], "bar")
				assert.Equal(t, subjectID, sub.Attributes["sub"])
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			endpointCalled = false
			responseHeaders = nil
			responseContentType = ""
			responseContent = nil

			checkRequest = func(*http.Request) { t.Helper() }

			instructServer := x.IfThenElse(tc.instructServer != nil,
				tc.instructServer,
				func(t *testing.T) { t.Helper() })

			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T,
					ctx *heimdallmocks.MockContext,
					cch *mocks.MockCache,
					ads *mockAuthDataGetter,
					auth *jwtAuthenticator,
				) {
					t.Helper()
				})

			ads := &mockAuthDataGetter{}
			tc.authenticator.ads = ads

			cch := &mocks.MockCache{}

			ctx := &heimdallmocks.MockContext{}
			ctx.On("AppContext").Return(cache.WithContext(context.Background(), cch))

			configureMocks(t, ctx, cch, ads, tc.authenticator)
			instructServer(t)

			// WHEN
			sub, err := tc.authenticator.Execute(ctx)

			// THEN
			tc.assert(t, err, sub)

			ctx.AssertExpectations(t)
			cch.AssertExpectations(t)
			ads.AssertExpectations(t)
		})
	}
}

func setup(t *testing.T, keyid, subject, issuer, audience string, uniqueKey bool) ([]byte, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: privateKey.Public(), KeyID: keyid, Algorithm: string(jose.PS512)},
		},
	}

	if !uniqueKey {
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key: privateKey.Public(), KeyID: keyid, Algorithm: string(jose.PS512),
		})
	}

	rawJwks, err := json.Marshal(jwks)
	require.NoError(t, err)

	signerOpts := jose.SignerOptions{}
	signerOpts.WithType("JWT").WithHeader("kid", keyid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS512, Key: privateKey}, &signerOpts)
	require.NoError(t, err)

	builder := jwt.Signed(signer)
	builder = builder.Claims(map[string]interface{}{
		"sub": subject,
		"iss": issuer,
		"jti": "foo",
		"iat": time.Now().Unix() - 1,
		"nbf": time.Now().Unix() - 1,
		"exp": time.Now().Unix() + 2,
		"aud": []string{audience},
		"scp": []string{"foo", "bar"},
	})
	rawJwt, err := builder.CompactSerialize()
	require.NoError(t, err)

	return rawJwks, rawJwt
}
