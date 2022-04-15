package authenticators

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/oauth2"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/pipeline/testsupport"
)

func TestCreateOAuth2IntrospectionAuthenticator(t *testing.T) {
	testCases := []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, a *oauth2IntrospectionAuthenticator)
	}{
		{
			uc: "missing introspection url config",
			config: []byte(`
introspection_response_assertions:
  issuers:
    - foobar
session:
  subject_from: some_template
`),
			assert: func(t *testing.T, err error, a *oauth2IntrospectionAuthenticator) {
				t.Helper()
				assert.Error(t, err)
			},
		},
		{
			uc: "missing assertions config",
			config: []byte(`
introspection_endpoint:
  url: foobar.local
session:
  subject_from: some_template
`),
			assert: func(t *testing.T, err error, a *oauth2IntrospectionAuthenticator) {
				t.Helper()
				assert.Error(t, err)
			},
		},
		{
			uc: "missing session config",
			config: []byte(`
introspection_endpoint:
  url: foobar.local
introspection_response_assertions:
  issuers:
    - foobar
`),
			assert: func(t *testing.T, err error, a *oauth2IntrospectionAuthenticator) {
				t.Helper()
				assert.Error(t, err)
			},
		},
		{
			uc: "valid config with defaults",
			config: []byte(`
introspection_endpoint:
  url: foobar.local
introspection_response_assertions:
  issuers:
    - foobar
session:
  subject_from: some_template
`),
			assert: func(t *testing.T, err error, auth *oauth2IntrospectionAuthenticator) {
				t.Helper()
				assert.NoError(t, err)

				// assert endpoint config
				assert.Equal(t, "foobar.local", auth.e.URL)
				assert.Equal(t, http.MethodPost, auth.e.Method)
				assert.Len(t, auth.e.Headers, 2)
				assert.Contains(t, auth.e.Headers, "Content-Type")
				assert.Equal(t, auth.e.Headers["Content-Type"], "application/x-www-form-urlencoded")
				assert.Contains(t, auth.e.Headers, "Accept-Type")
				assert.Equal(t, auth.e.Headers["Accept-Type"], "application/json")
				assert.Nil(t, auth.e.AuthStrategy)
				assert.Nil(t, auth.e.Retry)

				// assert assertions
				assert.Len(t, auth.a.AllowedAlgorithms, len(defaultAllowedAlgorithms()))
				assert.ElementsMatch(t, auth.a.AllowedAlgorithms, defaultAllowedAlgorithms())
				assert.Len(t, auth.a.TrustedIssuers, 1)
				assert.Contains(t, auth.a.TrustedIssuers, "foobar")
				assert.NoError(t, auth.a.ScopesMatcher.MatchScopes([]string{}))
				assert.Equal(t, time.Duration(0), auth.a.ValidityLeeway)
				assert.Empty(t, auth.a.TargetAudiences)

				// assert ttl
				assert.Nil(t, auth.ttl)

				// assert token extractor settings
				assert.IsType(t, extractors.CompositeExtractStrategy{}, auth.adg)
				assert.Contains(t, auth.adg, extractors.HeaderValueExtractStrategy{Name: "Authorization", Prefix: "Bearer"})
				assert.Contains(t, auth.adg, extractors.CookieValueExtractStrategy{Name: "access_token"})
				assert.Contains(t, auth.adg, extractors.QueryParameterExtractStrategy{Name: "access_token"})

				// assert subject factory
				assert.NotNil(t, auth.sf)
			},
		},
	}

	for _, tc := range testCases {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			a, err := newOAuth2IntrospectionAuthenticator(conf)

			// THEN
			tc.assert(t, err, a)
		})
	}
}

func TestCreateOAuth2IntrospectionAuthenticatorFromPrototype(t *testing.T) {
	for _, tc := range []struct {
		uc              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *oauth2IntrospectionAuthenticator,
			configured *oauth2IntrospectionAuthenticator)
	}{
		{
			uc: "prototype config without cache, target config with overwrites without cache",
			prototypeConfig: []byte(`
introspection_endpoint:
  url: foobar.local
introspection_response_assertions:
  issuers:
    - foobar
session:
  subject_from: some_template`),
			config: []byte(`
introspection_response_assertions:
  issuers:
    - barfoo
  allowed_algorithms:
    - ES512
`),
			assert: func(t *testing.T, err error, prototype *oauth2IntrospectionAuthenticator,
				configured *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.adg, configured.adg)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.a, configured.a)

				assert.NoError(t, configured.a.ScopesMatcher.MatchScopes([]string{}))
				assert.Empty(t, configured.a.TargetAudiences)
				assert.ElementsMatch(t, configured.a.TrustedIssuers, []string{"barfoo"})
				assert.ElementsMatch(t, configured.a.AllowedAlgorithms, []string{string(jose.ES512)})

				assert.Nil(t, prototype.ttl)
				assert.Equal(t, prototype.ttl, configured.ttl)
			},
		},
		{
			uc: "prototype config without cache, target config with cache overwrite",
			prototypeConfig: []byte(`
introspection_endpoint:
  url: foobar.local
introspection_response_assertions:
  issuers:
    - foobar
session:
  subject_from: some_template`),
			config: []byte(`cache_ttl: 5s`),
			assert: func(t *testing.T, err error, prototype *oauth2IntrospectionAuthenticator,
				configured *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.adg, configured.adg)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.Equal(t, prototype.a, configured.a)

				assert.Nil(t, prototype.ttl)
				assert.Equal(t, 5*time.Second, *configured.ttl)
			},
		},
		{
			uc: "valid prototype config, no target config",
			prototypeConfig: []byte(`
introspection_endpoint:
  url: foobar.local
introspection_response_assertions:
  issuers:
    - foobar
session:
  subject_from: some_template`),
			config: []byte{},
			assert: func(t *testing.T, err error, prototype *oauth2IntrospectionAuthenticator,
				configured *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc: "prototype config with cache, target config with overwrites including cache",
			prototypeConfig: []byte(`
introspection_endpoint:
  url: foobar.local
introspection_response_assertions:
  issuers:
    - foobar
session:
  subject_from: some_template
cache_ttl: 5s`),
			config: []byte(`
introspection_response_assertions:
  issuers:
    - barfoo
cache_ttl: 15s
`),
			assert: func(t *testing.T, err error, prototype *oauth2IntrospectionAuthenticator,
				configured *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.adg, configured.adg)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.a, configured.a)
				assert.ElementsMatch(t, configured.a.TrustedIssuers, []string{"barfoo"})

				assert.Equal(t, 5*time.Second, *prototype.ttl)
				assert.Equal(t, 15*time.Second, *configured.ttl)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newOAuth2IntrospectionAuthenticator(pc)
			require.NoError(t, err)

			// WHEN
			auth, err := prototype.WithConfig(conf)

			// THEN
			oaia, ok := auth.(*oauth2IntrospectionAuthenticator)
			require.True(t, ok)

			tc.assert(t, err, prototype, oaia)
		})
	}
}

func TestExecutionOfOAuth2IntrospectionAuthenticator(t *testing.T) {
	// GIVEN
	var (
		receivedAcceptType    string
		receivedContentType   string
		receivedTokenTypeHint string
		receivedToken         string
		endpointCalled        bool
	)

	tokenValue := "foooooobaaaaar"
	subjectID := "foo"
	issuer := "foobar"
	audience := "bar"
	attrs := map[string]any{
		"active":     true,
		"scope":      "foo bar",
		"username":   "unknown",
		"token_type": "Bearer",
		"aud":        audience,
		"sub":        subjectID,
		"iss":        issuer,
		"iat":        time.Now().Unix(),
		"nbf":        time.Now().Unix(),
		"exp":        time.Now().Unix() + 30,
	}

	rawIntrospectResponse, err := json.Marshal(attrs)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpointCalled = true

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		assert.NoError(t, r.ParseForm())

		receivedAcceptType = r.Header.Get("Accept-Type")
		receivedContentType = r.Header.Get("Content-Type")
		receivedTokenTypeHint = r.Form.Get("token_type_hint")
		receivedToken = r.Form.Get("token")

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(rawIntrospectResponse)))

		_, err := w.Write(rawIntrospectResponse)
		assert.NoError(t, err)
	}))
	defer srv.Close()

	for _, tc := range []struct {
		uc                      string
		configureTestOverwrites func()
		configureCache          func(cch *testsupport.MockCache) *time.Duration
		configureAuthDataGetter func(cch *mockAuthDataGetter, ctx *testsupport.MockContext)
		configureSubjectFactory func(sf *testsupport.MockSubjectFactory)
		assert                  func(t *testing.T, err error, sub *subject.Subject)
	}{
		{
			uc:                      "successful with cache disabled",
			configureTestOverwrites: func() {},
			configureCache: func(cch *testsupport.MockCache) *time.Duration {
				t.Helper()

				cch.On("Get", mock.Anything).Return(nil)

				cacheTTL := 0 * time.Second

				return &cacheTTL
			},
			configureAuthDataGetter: func(adg *mockAuthDataGetter, ctx *testsupport.MockContext) {
				t.Helper()

				adg.On("GetAuthData", ctx).Return(dummyAuthData{Val: tokenValue}, nil)
			},
			configureSubjectFactory: func(sf *testsupport.MockSubjectFactory) {
				t.Helper()

				sf.On("CreateSubject", rawIntrospectResponse).
					Return(&subject.Subject{ID: subjectID, Attributes: attrs}, nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.NoError(t, err)

				// assert networking
				assert.Equal(t, "application/x-www-form-urlencoded", receivedContentType)
				assert.Equal(t, "application/json", receivedAcceptType)
				assert.Equal(t, tokenValue, receivedToken)
				assert.Equal(t, "access_token", receivedTokenTypeHint)

				// assert subject
				assert.NotNil(t, sub)
				assert.Equal(t, subjectID, sub.ID)
				assert.Equal(t, attrs, sub.Attributes)
			},
		},
		{
			uc:                      "successful with usage of default cache ttl and cache miss",
			configureTestOverwrites: func() {},
			configureCache: func(cch *testsupport.MockCache) *time.Duration {
				t.Helper()

				cch.On("Get", mock.Anything).Return(nil)
				cch.On("Set", mock.Anything, rawIntrospectResponse, mock.MatchedBy(
					func(dur time.Duration) bool {
						exp := attrs["exp"]
						expDur, ok := exp.(int64)

						require.True(t, ok)

						calcDur := time.Duration(expDur-time.Now().Unix()) * time.Second

						return calcDur > dur
					}))

				return nil
			},
			configureAuthDataGetter: func(adg *mockAuthDataGetter, ctx *testsupport.MockContext) {
				t.Helper()

				adg.On("GetAuthData", ctx).Return(dummyAuthData{Val: tokenValue}, nil)
			},
			configureSubjectFactory: func(sf *testsupport.MockSubjectFactory) {
				t.Helper()

				sf.On("CreateSubject", rawIntrospectResponse).
					Return(&subject.Subject{ID: subjectID, Attributes: attrs}, nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.NoError(t, err)

				// assert networking
				assert.Equal(t, "application/x-www-form-urlencoded", receivedContentType)
				assert.Equal(t, "application/json", receivedAcceptType)
				assert.Equal(t, tokenValue, receivedToken)
				assert.Equal(t, "access_token", receivedTokenTypeHint)

				// assert subject
				assert.NotNil(t, sub)
				assert.Equal(t, subjectID, sub.ID)
				assert.Equal(t, attrs, sub.Attributes)
			},
		},
		{
			uc:                      "successful with usage of configured cache ttl and cache miss",
			configureTestOverwrites: func() {},
			configureCache: func(cch *testsupport.MockCache) *time.Duration {
				t.Helper()

				cacheTTL := 20 * time.Second

				cch.On("Get", mock.Anything).Return(nil)
				cch.On("Set", mock.Anything, rawIntrospectResponse, mock.MatchedBy(
					func(dur time.Duration) bool { return dur == cacheTTL }))

				return &cacheTTL
			},
			configureAuthDataGetter: func(adg *mockAuthDataGetter, ctx *testsupport.MockContext) {
				t.Helper()

				adg.On("GetAuthData", ctx).Return(dummyAuthData{Val: tokenValue}, nil)
			},
			configureSubjectFactory: func(sf *testsupport.MockSubjectFactory) {
				t.Helper()

				sf.On("CreateSubject", rawIntrospectResponse).
					Return(&subject.Subject{ID: subjectID, Attributes: attrs}, nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.NoError(t, err)

				// assert networking
				assert.Equal(t, "application/x-www-form-urlencoded", receivedContentType)
				assert.Equal(t, "application/json", receivedAcceptType)
				assert.Equal(t, tokenValue, receivedToken)
				assert.Equal(t, "access_token", receivedTokenTypeHint)

				// assert subject
				assert.NotNil(t, sub)
				assert.Equal(t, subjectID, sub.ID)
				assert.Equal(t, attrs, sub.Attributes)
			},
		},
		{
			uc:                      "successful using valid cached results using default cache ttl",
			configureTestOverwrites: func() {},
			configureCache: func(cch *testsupport.MockCache) *time.Duration {
				t.Helper()

				cch.On("Get", mock.Anything).Return(rawIntrospectResponse)

				return nil
			},
			configureAuthDataGetter: func(adg *mockAuthDataGetter, ctx *testsupport.MockContext) {
				t.Helper()

				adg.On("GetAuthData", ctx).Return(dummyAuthData{Val: tokenValue}, nil)
			},
			configureSubjectFactory: func(sf *testsupport.MockSubjectFactory) {
				t.Helper()

				sf.On("CreateSubject", rawIntrospectResponse).
					Return(&subject.Subject{ID: subjectID, Attributes: attrs}, nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.NoError(t, err)

				// assert networking
				assert.False(t, endpointCalled)

				// assert subject
				assert.NotNil(t, sub)
				assert.Equal(t, subjectID, sub.ID)
				assert.Equal(t, attrs, sub.Attributes)
			},
		},
		{
			uc:                      "successful using invalid cached results using default cache ttl",
			configureTestOverwrites: func() {},
			configureCache: func(cch *testsupport.MockCache) *time.Duration {
				t.Helper()

				cch.On("Get", mock.Anything).Return(attrs)
				cch.On("Set", mock.Anything, rawIntrospectResponse, mock.MatchedBy(
					func(dur time.Duration) bool {
						exp := attrs["exp"]
						expDur, ok := exp.(int64)

						require.True(t, ok)

						calcDur := time.Duration(expDur-time.Now().Unix()) * time.Second

						return calcDur > dur
					}))
				cch.On("Delete", mock.Anything)

				return nil
			},
			configureAuthDataGetter: func(adg *mockAuthDataGetter, ctx *testsupport.MockContext) {
				t.Helper()

				adg.On("GetAuthData", ctx).Return(dummyAuthData{Val: tokenValue}, nil)
			},
			configureSubjectFactory: func(sf *testsupport.MockSubjectFactory) {
				t.Helper()

				sf.On("CreateSubject", rawIntrospectResponse).
					Return(&subject.Subject{ID: subjectID, Attributes: attrs}, nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.NoError(t, err)

				// assert networking
				assert.True(t, endpointCalled)
				assert.Equal(t, "application/x-www-form-urlencoded", receivedContentType)
				assert.Equal(t, "application/json", receivedAcceptType)
				assert.Equal(t, tokenValue, receivedToken)
				assert.Equal(t, "access_token", receivedTokenTypeHint)

				// assert subject
				assert.NotNil(t, sub)
				assert.Equal(t, subjectID, sub.ID)
				assert.Equal(t, attrs, sub.Attributes)
			},
		},
		{
			uc:                      "erroneous with failing getting token from request",
			configureTestOverwrites: func() {},
			configureCache: func(cch *testsupport.MockCache) *time.Duration {
				t.Helper()

				return nil
			},
			configureAuthDataGetter: func(adg *mockAuthDataGetter, ctx *testsupport.MockContext) {
				t.Helper()

				adg.On("GetAuthData", ctx).Return(nil, testsupport.ErrTestPurpose)
			},
			configureSubjectFactory: func(sf *testsupport.MockSubjectFactory) {
				t.Helper()
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				assert.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Nil(t, sub)
			},
		},
		{
			uc: "erroneous with failing to create subject from introspection response",
			configureTestOverwrites: func() {
			},
			configureCache: func(cch *testsupport.MockCache) *time.Duration {
				t.Helper()

				cacheTTL := 20 * time.Second

				cch.On("Get", mock.Anything).Return(nil)
				cch.On("Set", mock.Anything, rawIntrospectResponse, mock.MatchedBy(
					func(dur time.Duration) bool { return dur == cacheTTL }))

				return &cacheTTL
			},
			configureAuthDataGetter: func(adg *mockAuthDataGetter, ctx *testsupport.MockContext) {
				t.Helper()

				adg.On("GetAuthData", ctx).Return(dummyAuthData{Val: tokenValue}, nil)
			},
			configureSubjectFactory: func(sf *testsupport.MockSubjectFactory) {
				t.Helper()

				sf.On("CreateSubject", rawIntrospectResponse).
					Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				assert.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Nil(t, sub)
			},
		},
		{
			uc: "erroneous with failing introspection response validation",
			configureTestOverwrites: func() {
				attrs = map[string]any{"active": false}
				rawIntrospectResponse, err = json.Marshal(attrs)

				require.NoError(t, err)
			},
			configureCache: func(cch *testsupport.MockCache) *time.Duration {
				t.Helper()

				cacheTTL := 20 * time.Second

				cch.On("Get", mock.Anything).Return(nil)

				return &cacheTTL
			},
			configureAuthDataGetter: func(adg *mockAuthDataGetter, ctx *testsupport.MockContext) {
				t.Helper()

				adg.On("GetAuthData", ctx).Return(dummyAuthData{Val: tokenValue}, nil)
			},
			configureSubjectFactory: func(sf *testsupport.MockSubjectFactory) {
				t.Helper()
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				assert.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Nil(t, sub)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			receivedToken = ""
			receivedTokenTypeHint = ""
			receivedContentType = ""
			receivedAcceptType = ""
			endpointCalled = false

			tc.configureTestOverwrites()

			cch := &testsupport.MockCache{}
			ttl := tc.configureCache(cch)

			ctx := &testsupport.MockContext{}
			ctx.On("AppContext").Return(cache.WithContext(context.Background(), cch))

			adg := &mockAuthDataGetter{}
			tc.configureAuthDataGetter(adg, ctx)

			sf := &testsupport.MockSubjectFactory{}
			tc.configureSubjectFactory(sf)

			auth := oauth2IntrospectionAuthenticator{
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodPost,
					Headers: map[string]string{
						"Accept-Type":  "application/json",
						"Content-Type": "application/x-www-form-urlencoded",
					},
				},
				a: oauth2.Expectation{
					ScopesMatcher: oauth2.ScopesMatcher{
						Match:  oauth2.ExactScopeStrategy,
						Scopes: []string{"foo"},
					},
					TargetAudiences: []string{audience},
					TrustedIssuers:  []string{issuer},
					ValidityLeeway:  1 * time.Minute,
				},
				sf:  sf,
				adg: adg,
				ttl: ttl,
			}

			// WHEN
			sub, err := auth.Execute(ctx)

			// THEN
			tc.assert(t, err, sub)

			// assert mocks
			cch.AssertExpectations(t)
			adg.AssertExpectations(t)
			sf.AssertExpectations(t)
		})
	}
}
