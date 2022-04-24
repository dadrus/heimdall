package authenticators

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/pipeline/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/oauth2"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/pipeline/testsupport"
)

func TestCreateJwtAuthenticator(t *testing.T) {
	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, a *jwtAuthenticator)
	}{
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
				assert.Error(t, err)
			},
		},
		{
			uc: "missing trusted_issuers config",
			config: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  audiences:
    - foobar
session:
  subject_id_from: some_template`),
			assert: func(t *testing.T, err error, a *jwtAuthenticator) {
				t.Helper()
				assert.Error(t, err)
			},
		},
		{
			uc: "config with undefined fields",
			config: []byte(`
jwks_endpoint:
  url: http://test.com
jwt_from:
  - header: foo-header
assertions:
  issuers:
    - foobar
foo: bar`),
			assert: func(t *testing.T, err error, a *jwtAuthenticator) {
				t.Helper()
				assert.Error(t, err)
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
				assert.IsType(t, extractors.CompositeExtractStrategy{}, auth.adg)
				assert.Contains(t, auth.adg, extractors.HeaderValueExtractStrategy{Name: "Authorization", Prefix: "Bearer"})
				assert.Contains(t, auth.adg, extractors.CookieValueExtractStrategy{Name: "access_token"})
				assert.Contains(t, auth.adg, extractors.QueryParameterExtractStrategy{Name: "access_token"})

				// assertions settings
				assert.NoError(t, auth.a.ScopesMatcher.MatchScopes([]string{}))
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
				assert.Nil(t, auth.ttl)
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
				assert.IsType(t, extractors.CompositeExtractStrategy{}, auth.adg)
				assert.Contains(t, auth.adg, extractors.HeaderValueExtractStrategy{Name: "Authorization", Prefix: "Bearer"})
				assert.Contains(t, auth.adg, extractors.CookieValueExtractStrategy{Name: "access_token"})
				assert.Contains(t, auth.adg, extractors.QueryParameterExtractStrategy{Name: "access_token"})

				// assertions settings
				assert.NoError(t, auth.a.ScopesMatcher.MatchScopes([]string{}))
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
				assert.Equal(t, 5*time.Second, *auth.ttl)
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
				assert.IsType(t, extractors.CompositeExtractStrategy{}, auth.adg)
				assert.Len(t, auth.adg, 1)
				assert.Contains(t, auth.adg, &extractors.HeaderValueExtractStrategy{Name: "foo-header"})

				// assertions settings
				assert.NotNil(t, auth.a.ScopesMatcher)
				assert.NoError(t, auth.a.ScopesMatcher.MatchScopes([]string{"foo"}))
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
				assert.Nil(t, auth.ttl)
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

func setup(t *testing.T, subject, issuer, audience string) ([]byte, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: privateKey.Public(), KeyID: "bar", Algorithm: string(jose.PS512)},
		},
	}
	rawJwks, err := json.Marshal(jwks)
	require.NoError(t, err)

	signerOpts := jose.SignerOptions{}
	signerOpts.WithType("JWT").WithHeader("kid", "bar")
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

func TestCreateJwtAuthenticatorFromPrototype(t *testing.T) {
	// nolint
	for _, tc := range []struct {
		uc              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *jwtAuthenticator, configured *jwtAuthenticator)
	}{
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
				// THEN
				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.adg, configured.adg)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.a, configured.a)

				assert.NoError(t, configured.a.ScopesMatcher.MatchScopes([]string{}))
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
				// THEN
				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.adg, configured.adg)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.a, configured.a)

				assert.NoError(t, configured.a.ScopesMatcher.MatchScopes([]string{}))
				assert.Empty(t, configured.a.TargetAudiences)
				assert.ElementsMatch(t, configured.a.TrustedIssuers, []string{"barfoo"})
				assert.ElementsMatch(t, configured.a.AllowedAlgorithms, []string{string(jose.ES512)})

				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, 5*time.Second, *configured.ttl)
			},
		},
		{
			uc: "prototype config with cache, config without but with overwrites cache",
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
				// THEN
				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.adg, configured.adg)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.a, configured.a)

				assert.NoError(t, configured.a.ScopesMatcher.MatchScopes([]string{}))
				assert.Empty(t, configured.a.TargetAudiences)
				assert.ElementsMatch(t, configured.a.TrustedIssuers, []string{"barfoo"})
				assert.ElementsMatch(t, configured.a.AllowedAlgorithms, []string{string(jose.ES512)})

				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, 5*time.Second, *configured.ttl)
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
				// THEN
				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.adg, configured.adg)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.Equal(t, prototype.a, configured.a)

				assert.Equal(t, 5*time.Second, *prototype.ttl)
				assert.Equal(t, 15*time.Second, *configured.ttl)
			},
		},
		{
			uc: "valid prototype config and empty target config",
			prototypeConfig: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  issuers:
    - foobar
cache_ttl: 5s`),
			config: []byte{},
			assert: func(t *testing.T, err error, prototype *jwtAuthenticator, configured *jwtAuthenticator) {
				// THEN
				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newJwtAuthenticator(pc)

			// WHEN
			auth, err := prototype.WithConfig(conf)

			// THEN
			jwta, ok := auth.(*jwtAuthenticator)
			require.True(t, ok)

			tc.assert(t, err, prototype, jwta)
		})
	}
}

func TestSuccessfulExecutionOfJwtAuthenticatorWithoutCacheUsage(t *testing.T) {
	t.Parallel()

	// GIVEN
	var receivedAcceptType string

	subjectID := "foo"
	issuer := "foobar"
	audience := "bar"
	jwksRaw, jwtRaw := setup(t, subjectID, issuer, audience)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		receivedAcceptType = r.Header.Get("Accept-Type")

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(jwksRaw)))

		_, err := w.Write(jwksRaw)
		assert.NoError(t, err)
	}))
	defer srv.Close()

	as := oauth2.Expectation{
		ScopesMatcher: oauth2.ScopesMatcher{
			Match:  oauth2.ExactScopeStrategy,
			Scopes: []string{"foo"},
		},
		TargetAudiences:   []string{audience},
		TrustedIssuers:    []string{issuer},
		AllowedAlgorithms: []string{string(jose.PS512)},
		ValidityLeeway:    1 * time.Minute,
	}

	cch := &testsupport.MockCache{}

	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(cache.WithContext(context.Background(), cch))

	adg := &mockAuthDataGetter{}
	adg.On("GetAuthData", ctx).Return(dummyAuthData{Val: jwtRaw}, nil)

	encJwtPayload := strings.Split(jwtRaw, ".")[1]
	rawPaload, err := base64.RawStdEncoding.DecodeString(encJwtPayload)
	require.NoError(t, err)

	var attrs map[string]any
	err = json.Unmarshal(rawPaload, &attrs)
	require.NoError(t, err)

	sf := &testsupport.MockSubjectFactory{}
	sf.On("CreateSubject", rawPaload).Return(&subject.Subject{ID: subjectID, Attributes: attrs}, nil)

	auth := jwtAuthenticator{
		e: endpoint.Endpoint{
			URL:     srv.URL,
			Method:  http.MethodGet,
			Headers: map[string]string{"Accept-Type": "application/json"},
		},
		a:   as,
		sf:  sf,
		adg: adg,
	}

	// WHEN
	sub, err := auth.Execute(ctx)

	// THEN
	require.NoError(t, err)

	assert.NotNil(t, sub)
	assert.Equal(t, subjectID, sub.ID)
	assert.Equal(t, attrs, sub.Attributes)
	assert.Equal(t, "application/json", receivedAcceptType)

	ctx.AssertExpectations(t)
	sf.AssertExpectations(t)
	adg.AssertExpectations(t)
	cch.AssertExpectations(t)
}

func TestSuccessfulExecutionOfJwtAuthenticatorWithKeyFromCache(t *testing.T) {
	t.Parallel()

	// GIVEN
	ttlKey := 5 * time.Minute
	subjectID := "foo"
	issuer := "foobar"
	audience := "bar"
	jwksRaw, jwtRaw := setup(t, subjectID, issuer, audience)

	var jwks jose.JSONWebKeySet
	err := json.Unmarshal(jwksRaw, &jwks)
	require.NoError(t, err)

	token, err := jwt.ParseSigned(jwtRaw)
	require.NoError(t, err)

	sigKey := jwks.Key(token.Headers[0].KeyID)[0]

	as := oauth2.Expectation{
		ScopesMatcher: oauth2.ScopesMatcher{
			Match:  oauth2.ExactScopeStrategy,
			Scopes: []string{"foo"},
		},
		TargetAudiences:   []string{audience},
		TrustedIssuers:    []string{issuer},
		AllowedAlgorithms: []string{string(jose.PS512)},
		ValidityLeeway:    1 * time.Minute,
	}

	cch := &testsupport.MockCache{}
	cch.On("Get", mock.Anything).Return(&sigKey)

	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(cache.WithContext(context.Background(), cch))

	adg := &mockAuthDataGetter{}
	adg.On("GetAuthData", ctx).Return(dummyAuthData{Val: jwtRaw}, nil)

	encJwtPayload := strings.Split(jwtRaw, ".")[1]
	rawPaload, err := base64.RawStdEncoding.DecodeString(encJwtPayload)
	require.NoError(t, err)

	var attrs map[string]any
	err = json.Unmarshal(rawPaload, &attrs)
	require.NoError(t, err)

	sf := &testsupport.MockSubjectFactory{}
	sf.On("CreateSubject", rawPaload).Return(&subject.Subject{ID: subjectID, Attributes: attrs}, nil)

	auth := jwtAuthenticator{
		e: endpoint.Endpoint{
			URL:     "foobar.local",
			Method:  http.MethodGet,
			Headers: map[string]string{"Accept-Type": "application/json"},
		},
		a:   as,
		sf:  sf,
		adg: adg,
		ttl: &ttlKey,
	}

	// WHEN
	sub, err := auth.Execute(ctx)

	// THEN
	require.NoError(t, err)

	assert.NotNil(t, sub)
	assert.Equal(t, subjectID, sub.ID)
	assert.Equal(t, attrs, sub.Attributes)

	ctx.AssertExpectations(t)
	sf.AssertExpectations(t)
	adg.AssertExpectations(t)
	cch.AssertExpectations(t)
}

func TestSuccessfulExecutionOfJwtAuthenticatorWithCacheMiss(t *testing.T) {
	t.Parallel()

	// GIVEN
	var receivedAcceptType string

	subjectID := "foo"
	issuer := "foobar"
	audience := "bar"
	jwksRaw, jwtRaw := setup(t, subjectID, issuer, audience)
	keyTTL := 5 * time.Second

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		receivedAcceptType = r.Header.Get("Accept-Type")

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(jwksRaw)))

		_, err := w.Write(jwksRaw)
		assert.NoError(t, err)
	}))
	defer srv.Close()

	as := oauth2.Expectation{
		ScopesMatcher: oauth2.ScopesMatcher{
			Match:  oauth2.ExactScopeStrategy,
			Scopes: []string{"foo"},
		},
		TargetAudiences:   []string{audience},
		TrustedIssuers:    []string{issuer},
		AllowedAlgorithms: []string{string(jose.PS512)},
		ValidityLeeway:    1 * time.Minute,
	}

	cch := &testsupport.MockCache{}
	cch.On("Get", mock.Anything).Return(nil)
	cch.On("Set", mock.Anything, mock.IsType(&jose.JSONWebKey{}), keyTTL)

	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(cache.WithContext(context.Background(), cch))

	adg := &mockAuthDataGetter{}
	adg.On("GetAuthData", ctx).Return(dummyAuthData{Val: jwtRaw}, nil)

	encJwtPayload := strings.Split(jwtRaw, ".")[1]
	rawPaload, err := base64.RawStdEncoding.DecodeString(encJwtPayload)
	require.NoError(t, err)

	var attrs map[string]any
	err = json.Unmarshal(rawPaload, &attrs)
	require.NoError(t, err)

	sf := &testsupport.MockSubjectFactory{}
	sf.On("CreateSubject", rawPaload).Return(&subject.Subject{ID: subjectID, Attributes: attrs}, nil)

	auth := jwtAuthenticator{
		e: endpoint.Endpoint{
			URL:     srv.URL,
			Method:  http.MethodGet,
			Headers: map[string]string{"Accept-Type": "application/json"},
		},
		a:   as,
		sf:  sf,
		adg: adg,
		ttl: &keyTTL,
	}

	// WHEN
	sub, err := auth.Execute(ctx)

	// THEN
	require.NoError(t, err)

	assert.NotNil(t, sub)
	assert.Equal(t, subjectID, sub.ID)
	assert.Equal(t, attrs, sub.Attributes)
	assert.Equal(t, "application/json", receivedAcceptType)

	ctx.AssertExpectations(t)
	sf.AssertExpectations(t)
	adg.AssertExpectations(t)
	cch.AssertExpectations(t)
}
