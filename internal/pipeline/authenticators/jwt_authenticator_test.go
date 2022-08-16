package authenticators

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/dadrus/heimdall/internal/keystore"
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

const (
	kidKeyWithoutCert = "key_without_cert"
	kidKeyWithCert    = "key_with_cert"
)

// nolint: maintidx
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
				assert.Len(t, auth.ads, 3)
				assert.Contains(t, auth.ads, extractors.HeaderValueExtractStrategy{Name: "Authorization", Schema: "Bearer"})
				assert.Contains(t, auth.ads, extractors.QueryParameterExtractStrategy{Name: "access_token"})
				assert.Contains(t, auth.ads, extractors.BodyParameterExtractStrategy{Name: "access_token"})

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

				assert.False(t, auth.IsFallbackOnErrorAllowed())
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
				assert.Len(t, auth.ads, 3)
				assert.Contains(t, auth.ads, extractors.HeaderValueExtractStrategy{Name: "Authorization", Schema: "Bearer"})
				assert.Contains(t, auth.ads, extractors.QueryParameterExtractStrategy{Name: "access_token"})
				assert.Contains(t, auth.ads, extractors.BodyParameterExtractStrategy{Name: "access_token"})

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
    schema: foo
  - query_parameter: foo_query_param
  - body_parameter: foo_body_param
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
				assert.Len(t, auth.ads, 3)
				assert.Contains(t, auth.ads, &extractors.HeaderValueExtractStrategy{
					Name: "foo-header", Schema: "foo",
				})
				assert.Contains(t, auth.ads, &extractors.QueryParameterExtractStrategy{Name: "foo_query_param"})
				assert.Contains(t, auth.ads, &extractors.BodyParameterExtractStrategy{Name: "foo_body_param"})

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
		{
			uc: "with defaults and fallback on error allowed",
			config: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  issuers:
    - foobar
allow_fallback_on_error: true`),
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
				assert.Len(t, auth.ads, 3)
				assert.Contains(t, auth.ads, extractors.HeaderValueExtractStrategy{Name: "Authorization", Schema: "Bearer"})
				assert.Contains(t, auth.ads, extractors.QueryParameterExtractStrategy{Name: "access_token"})
				assert.Contains(t, auth.ads, extractors.BodyParameterExtractStrategy{Name: "access_token"})

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

				assert.True(t, auth.IsFallbackOnErrorAllowed())
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

// nolint: maintidx
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
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
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
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
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
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
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
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
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
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
			},
		},
		{
			uc: "prototype with defaults, configured allows fallback on errors",
			prototypeConfig: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  issuers:
    - foobar
cache_ttl: 5s`),
			config: []byte(`
allow_fallback_on_error: true
`),
			assert: func(t *testing.T, err error, prototype *jwtAuthenticator, configured *jwtAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.Equal(t, prototype.a, configured.a)

				assert.NotEqual(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.True(t, configured.IsFallbackOnErrorAllowed())
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

	ks := createKS(t)
	keyOnlyEntry, err := ks.GetKey(kidKeyWithoutCert)
	require.NoError(t, err)
	keyAndCertEntry, err := ks.GetKey(kidKeyWithCert)
	require.NoError(t, err)

	jwksWithDuplicateEntries, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		keyOnlyEntry.JWK(), keyOnlyEntry.JWK(),
	}})
	require.NoError(t, err)

	jwksWithOneKeyOnlyEntry, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		keyOnlyEntry.JWK(),
	}})
	require.NoError(t, err)

	jwksWithOneEntryWithKeyOnlyAndOneCertificate, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		keyOnlyEntry.JWK(), keyAndCertEntry.JWK(),
	}})
	require.NoError(t, err)

	subjectID := "foo"
	issuer := "foobar"
	audience := "bar"

	jwtSignedWithKeyOnlyJWK := createJWT(t, keyOnlyEntry, subjectID, issuer, audience)
	jwtSignedWithKeyAndCertJWK := createJWT(t, keyAndCertEntry, subjectID, issuer, audience)

	// uniqueJWKSRaw, uniqueJWTRaw := setup(t, keyID, subjectID, issuer, audience, true)
	// notUniqueJWKSRaw, notUniqueJWTRaw := setup(t, keyID, subjectID, issuer, audience, false)

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
				assert.NotErrorIs(t, err, heimdall.ErrArgument)
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
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "JWS format must have three parts")
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
				assert.ErrorIs(t, err, heimdall.ErrArgument)
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

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: jwtSignedWithKeyOnlyJWK}, nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.NotErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "JWKS endpoint failed")
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

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: jwtSignedWithKeyOnlyJWK}, nil)
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
				assert.NotErrorIs(t, err, heimdall.ErrArgument)
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

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: jwtSignedWithKeyOnlyJWK}, nil)
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
				assert.NotErrorIs(t, err, heimdall.ErrArgument)
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

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: jwtSignedWithKeyOnlyJWK}, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				responseCode = http.StatusOK
				responseContent = jwksWithDuplicateEntries
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.NotErrorIs(t, err, heimdall.ErrArgument)
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

				cacheKey := auth.calculateCacheKey(kidKeyWithoutCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: jwtSignedWithKeyOnlyJWK}, nil)
				cch.On("Get", cacheKey).Return(&keys[0])
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.NotErrorIs(t, err, heimdall.ErrArgument)
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
				a:   oauth2.Expectation{AllowedAlgorithms: []string{"ES384"}},
				ttl: 10 * time.Second,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey(kidKeyWithCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: jwtSignedWithKeyAndCertJWK}, nil)
				cch.On("Get", cacheKey).Return(&keys[0])
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.NotErrorIs(t, err, heimdall.ErrArgument)
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
				a:   oauth2.Expectation{AllowedAlgorithms: []string{"ES384"}, TrustedIssuers: []string{"untrusted"}},
				ttl: 10 * time.Second,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.MockContext,
				cch *mocks.MockCache,
				ads *mockAuthDataGetter,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey(kidKeyWithoutCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: jwtSignedWithKeyOnlyJWK}, nil)
				cch.On("Get", cacheKey).Return(&keys[0])
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.NotErrorIs(t, err, heimdall.ErrArgument)
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
					AllowedAlgorithms: []string{"ES384"},
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

				cacheKey := auth.calculateCacheKey(kidKeyWithoutCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: jwtSignedWithKeyOnlyJWK}, nil)
				cch.On("Get", cacheKey).Return(&keys[0])
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.NotErrorIs(t, err, heimdall.ErrArgument)
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
					AllowedAlgorithms: []string{"ES384"},
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

				cacheKey := auth.calculateCacheKey(kidKeyWithoutCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: jwtSignedWithKeyOnlyJWK}, nil)
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
			uc: "successful without cache hit using key only",
			authenticator: &jwtAuthenticator{
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
				a: oauth2.Expectation{
					AllowedAlgorithms: []string{"ES384"},
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

				cacheKey := auth.calculateCacheKey(kidKeyWithoutCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: jwtSignedWithKeyOnlyJWK}, nil)
				cch.On("Get", cacheKey).Return(nil)
				cch.On("Set", cacheKey, &keys[0], auth.ttl)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				responseCode = http.StatusOK
				responseContent = jwksWithOneKeyOnlyEntry
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
			uc: "successful without cache hit using key & cert only",
			authenticator: &jwtAuthenticator{
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
				a: oauth2.Expectation{
					AllowedAlgorithms: []string{"ES384"},
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

				cacheKey := auth.calculateCacheKey(kidKeyWithCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneEntryWithKeyOnlyAndOneCertificate, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithCert)

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: jwtSignedWithKeyAndCertJWK}, nil)
				cch.On("Get", cacheKey).Return(nil)
				cch.On("Set", cacheKey, &keys[0], auth.ttl)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				responseCode = http.StatusOK
				responseContent = jwksWithOneEntryWithKeyOnlyAndOneCertificate
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
					AllowedAlgorithms: []string{"ES384"},
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

				cacheKey := auth.calculateCacheKey(kidKeyWithoutCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				ads.On("GetAuthData", ctx).Return(dummyAuthData{Val: jwtSignedWithKeyOnlyJWK}, nil)
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
				responseContent = jwksWithOneKeyOnlyEntry
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

func createKS(t *testing.T) keystore.KeyStore {
	t.Helper()

	// ROOT CAs
	rootCA1, err := testsupport.NewRootCA("Test Root CA 1", time.Hour*24)
	require.NoError(t, err)

	// INT CA
	intCA1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	intCA1Cert, err := rootCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test Int CA 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithIsCA(),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&intCA1PrivKey.PublicKey, x509.ECDSAWithSHA384))
	require.NoError(t, err)

	intCA1 := testsupport.NewCA(intCA1PrivKey, intCA1Cert)

	// EE CERTS
	ee1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	ee1cert, err := intCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&ee1PrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
	require.NoError(t, err)

	ee2PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	pemBytes, err := testsupport.BuildPEM(
		testsupport.WithECDSAPrivateKey(ee1PrivKey, testsupport.WithPEMHeader("X-Key-ID", kidKeyWithCert)),
		testsupport.WithECDSAPrivateKey(ee2PrivKey, testsupport.WithPEMHeader("X-Key-ID", kidKeyWithoutCert)),
		testsupport.WithX509Certificate(ee1cert),
		testsupport.WithX509Certificate(intCA1Cert),
		testsupport.WithX509Certificate(rootCA1.Certificate),
	)
	require.NoError(t, err)

	ks, err := keystore.NewKeyStoreFromPEMBytes(pemBytes, "")
	require.NoError(t, err)

	return ks
}

func createJWT(t *testing.T, keyEntry *keystore.Entry, subject, issuer, audience string) string {
	signerOpts := jose.SignerOptions{}
	signerOpts.WithType("JWT").WithHeader("kid", keyEntry.KeyID)
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: keyEntry.JOSEAlgorithm(),
			Key:       keyEntry.PrivateKey,
		},
		&signerOpts)
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

	return rawJwt
}
