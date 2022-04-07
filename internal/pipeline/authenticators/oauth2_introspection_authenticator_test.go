package authenticators

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"

	"github.com/dadrus/heimdall/internal/pipeline/authenticators/extractors"
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
				configured *oauth2IntrospectionAuthenticator) {
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
				configured *oauth2IntrospectionAuthenticator) {
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
				configured *oauth2IntrospectionAuthenticator) {
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
				configured *oauth2IntrospectionAuthenticator) {
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
