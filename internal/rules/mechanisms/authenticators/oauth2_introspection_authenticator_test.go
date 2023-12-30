// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package authenticators

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/heimdall"
	heimdallmocks "github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
	mocks2 "github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/oauth2"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestOAuth2IntrospectionAuthenticatorCreate(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		uc     string
		id     string
		config []byte
		assert func(t *testing.T, err error, a *oauth2IntrospectionAuthenticator)
	}{
		{
			uc: "with unsupported fields",
			config: []byte(`
assertions:
  issuers:
    - foobar
subject:
  id: some_template
foo: bar
`),
			assert: func(t *testing.T, err error, _ *oauth2IntrospectionAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		{
			uc: "with missing introspection url config",
			config: []byte(`
assertions:
  issuers:
    - foobar
subject:
  id: some_template
`),
			assert: func(t *testing.T, err error, _ *oauth2IntrospectionAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'introspection_endpoint' is a required field")
			},
		},
		{
			uc: "with missing trusted issuers assertion config when not using metadata endpoint",
			config: []byte(`
introspection_endpoint:
  url: http://foobar.local
assertions:
  audience:
    - foobar
subject:
  id: some_template
`),
			assert: func(t *testing.T, err error, _ *oauth2IntrospectionAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'issuers' is a required field")
			},
		},
		{
			uc: "minimal introspection endpoint based config with malformed url",
			id: "auth1",
			config: []byte(`
introspection_endpoint:
  url: "{{ .IssuerName }}"
assertions:
  issuers:
    - foobar`),
			assert: func(t *testing.T, err error, _ *oauth2IntrospectionAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'introspection_endpoint'.'url' must be a valid URL")
			},
		},
		{
			uc: "with minimal introspection endpoint based config",
			id: "auth1",
			config: []byte(`
introspection_endpoint:
  url: http://foobar.local
assertions:
  issuers:
    - foobar
`),
			assert: func(t *testing.T, err error, auth *oauth2IntrospectionAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				// assert endpoint config
				_, ok := auth.r.(oauth2.ResolverAdapterFunc)
				require.True(t, ok)
				md, err := auth.r.Get(context.TODO(), nil)
				require.NoError(t, err)
				assert.Equal(t, "http://foobar.local", md.IntrospectionEndpoint.URL)
				assert.Equal(t, http.MethodPost, md.IntrospectionEndpoint.Method)
				assert.Len(t, md.IntrospectionEndpoint.Headers, 2)
				assert.Contains(t, md.IntrospectionEndpoint.Headers, "Content-Type")
				assert.Equal(t, "application/x-www-form-urlencoded", md.IntrospectionEndpoint.Headers["Content-Type"])
				assert.Contains(t, md.IntrospectionEndpoint.Headers, "Accept")
				assert.Equal(t, "application/json", md.IntrospectionEndpoint.Headers["Accept"])
				assert.Nil(t, md.IntrospectionEndpoint.AuthStrategy)
				assert.Nil(t, md.IntrospectionEndpoint.Retry)

				// assert assertions
				assert.Len(t, auth.a.AllowedAlgorithms, len(defaultAllowedAlgorithms()))
				assert.ElementsMatch(t, auth.a.AllowedAlgorithms, defaultAllowedAlgorithms())
				assert.Len(t, auth.a.TrustedIssuers, 1)
				assert.Contains(t, auth.a.TrustedIssuers, "foobar")
				require.NoError(t, auth.a.ScopesMatcher.Match([]string{}))
				assert.Equal(t, time.Duration(0), auth.a.ValidityLeeway)
				assert.Empty(t, auth.a.TargetAudiences)

				// assert ttl
				assert.Nil(t, auth.ttl)

				// assert token extractor settings
				assert.IsType(t, extractors.CompositeExtractStrategy{}, auth.ads)
				assert.Len(t, auth.ads, 3)
				assert.Contains(t, auth.ads, extractors.HeaderValueExtractStrategy{Name: "Authorization", Scheme: "Bearer"})
				assert.Contains(t, auth.ads, extractors.QueryParameterExtractStrategy{Name: "access_token"})
				assert.Contains(t, auth.ads, extractors.BodyParameterExtractStrategy{Name: "access_token"})

				// assert subject factory
				assert.NotNil(t, auth.sf)
				assert.IsType(t, &SubjectInfo{}, auth.sf)
				sess, ok := auth.sf.(*SubjectInfo)
				assert.True(t, ok)
				assert.Equal(t, "sub", sess.IDFrom)

				assert.False(t, auth.IsFallbackOnErrorAllowed())

				assert.Equal(t, "auth1", auth.ID())
			},
		},
		{
			uc: "with valid introspection endpoint based config with overwrites",
			id: "auth1",
			config: []byte(`
introspection_endpoint:
  url: http://test.com
  method: PATCH
  headers:
    Accept: application/foobar
token_source:
  - header: foo-header
    scheme: foo
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
subject:
  id: some_claim
cache_ttl: 5s
allow_fallback_on_error: true
`),
			assert: func(t *testing.T, err error, auth *oauth2IntrospectionAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				// assert endpoint config
				_, ok := auth.r.(oauth2.ResolverAdapterFunc)
				require.True(t, ok)
				md, err := auth.r.Get(context.TODO(), nil)
				require.NoError(t, err)
				assert.Equal(t, "http://test.com", md.IntrospectionEndpoint.URL)
				assert.Equal(t, http.MethodPatch, md.IntrospectionEndpoint.Method)
				assert.Len(t, md.IntrospectionEndpoint.Headers, 2)
				assert.Contains(t, md.IntrospectionEndpoint.Headers, "Content-Type")
				assert.Equal(t, "application/x-www-form-urlencoded", md.IntrospectionEndpoint.Headers["Content-Type"])
				assert.Contains(t, md.IntrospectionEndpoint.Headers, "Accept")
				assert.Equal(t, "application/foobar", md.IntrospectionEndpoint.Headers["Accept"])
				assert.Nil(t, md.IntrospectionEndpoint.AuthStrategy)
				assert.Nil(t, md.IntrospectionEndpoint.Retry)

				// assert assertions
				assert.Len(t, auth.a.AllowedAlgorithms, 1)
				assert.ElementsMatch(t, auth.a.AllowedAlgorithms, []string{"ES256"})
				assert.Len(t, auth.a.TrustedIssuers, 1)
				assert.Contains(t, auth.a.TrustedIssuers, "foobar")
				require.NoError(t, auth.a.ScopesMatcher.Match([]string{"foo"}))
				assert.Equal(t, time.Duration(0), auth.a.ValidityLeeway)
				assert.Empty(t, auth.a.TargetAudiences)

				// assert ttl
				assert.Equal(t, 5*time.Second, *auth.ttl)

				// assert token extractor settings
				assert.IsType(t, extractors.CompositeExtractStrategy{}, auth.ads)
				assert.Len(t, auth.ads, 3)
				assert.Contains(t, auth.ads, &extractors.HeaderValueExtractStrategy{Name: "foo-header", Scheme: "foo"})
				assert.Contains(t, auth.ads, &extractors.QueryParameterExtractStrategy{Name: "foo_query_param"})
				assert.Contains(t, auth.ads, &extractors.BodyParameterExtractStrategy{Name: "foo_body_param"})

				// assert subject factory
				assert.NotNil(t, auth.sf)
				assert.IsType(t, &SubjectInfo{}, auth.sf)
				sess, ok := auth.sf.(*SubjectInfo)
				assert.True(t, ok)
				assert.Equal(t, "some_claim", sess.IDFrom)

				assert.True(t, auth.IsFallbackOnErrorAllowed())

				assert.Equal(t, "auth1", auth.ID())
			},
		},
		{
			uc: "minimal metadata endpoint based configuration with malformed endpoint",
			id: "auth1",
			config: []byte(`
metadata_endpoint:
  url: "{{ .IssuerName }}"
`),
			assert: func(t *testing.T, err error, _ *oauth2IntrospectionAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'metadata_endpoint'.'url' must be a valid URL")
			},
		},
		{
			uc: "with minimal metadata endpoint based config",
			id: "auth1",
			config: []byte(`
metadata_endpoint:
  url: http://foobar.local
  disable_issuer_identifier_verification: true
`),
			assert: func(t *testing.T, err error, auth *oauth2IntrospectionAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				// assert endpoint config
				_, ok := auth.r.(oauth2.ResolverAdapterFunc)
				require.False(t, ok)

				// assert assertions
				assert.Len(t, auth.a.AllowedAlgorithms, len(defaultAllowedAlgorithms()))
				assert.ElementsMatch(t, auth.a.AllowedAlgorithms, defaultAllowedAlgorithms())
				assert.Empty(t, auth.a.TrustedIssuers, 1)
				require.NoError(t, auth.a.ScopesMatcher.Match([]string{}))
				assert.Equal(t, time.Duration(0), auth.a.ValidityLeeway)
				assert.Empty(t, auth.a.TargetAudiences)

				// assert ttl
				assert.Nil(t, auth.ttl)

				// assert token extractor settings
				assert.IsType(t, extractors.CompositeExtractStrategy{}, auth.ads)
				assert.Len(t, auth.ads, 3)
				assert.Contains(t, auth.ads, extractors.HeaderValueExtractStrategy{Name: "Authorization", Scheme: "Bearer"})
				assert.Contains(t, auth.ads, extractors.QueryParameterExtractStrategy{Name: "access_token"})
				assert.Contains(t, auth.ads, extractors.BodyParameterExtractStrategy{Name: "access_token"})

				// assert subject factory
				assert.NotNil(t, auth.sf)
				assert.IsType(t, &SubjectInfo{}, auth.sf)
				sess, ok := auth.sf.(*SubjectInfo)
				assert.True(t, ok)
				assert.Equal(t, "sub", sess.IDFrom)

				assert.False(t, auth.IsFallbackOnErrorAllowed())

				assert.Equal(t, "auth1", auth.ID())
			},
		},
	}

	for _, tc := range testCases {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			a, err := newOAuth2IntrospectionAuthenticator(tc.id, conf)

			// THEN
			tc.assert(t, err, a)
		})
	}
}

func TestOAuth2IntrospectionAuthenticatorWithConfig(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		id              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *oauth2IntrospectionAuthenticator,
			configured *oauth2IntrospectionAuthenticator)
	}{
		{
			uc: "without target config",
			id: "auth2",
			prototypeConfig: []byte(`
introspection_endpoint:
  url: http://foobar.local
assertions:
  issuers:
    - foobar
subject:
  id: some_template`),
			assert: func(t *testing.T, err error, prototype *oauth2IntrospectionAuthenticator,
				configured *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
				assert.Equal(t, "auth2", configured.ID())
			},
		},
		{
			uc: "with unsupported fields",
			prototypeConfig: []byte(`
introspection_endpoint:
  url: http://foobar.local
assertions:
  issuers:
    - foobar
subject:
  id: some_template`),
			config: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, _ *oauth2IntrospectionAuthenticator,
				_ *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		{
			uc: "with overwrites without cache",
			id: "auth2",
			prototypeConfig: []byte(`
introspection_endpoint:
  url: http://foobar.local
assertions:
  issuers:
    - foobar
  audience:
    - baz
subject:
  id: some_template`),
			config: []byte(`
assertions:
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

				assert.Equal(t, fmt.Sprintf("%v", prototype.r), fmt.Sprintf("%v", configured.r))
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.a, configured.a)

				require.NoError(t, configured.a.ScopesMatcher.Match([]string{}))
				assert.ElementsMatch(t, configured.a.TargetAudiences, []string{"baz"})
				assert.ElementsMatch(t, configured.a.TrustedIssuers, []string{"barfoo"})
				assert.ElementsMatch(t, configured.a.AllowedAlgorithms, []string{string(jose.ES512)})

				assert.Nil(t, prototype.ttl)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.Equal(t, "auth2", configured.ID())
			},
		},
		{
			uc: "prototype config without cache, target config with cache overwrite",
			id: "auth2",
			prototypeConfig: []byte(`
metadata_endpoint:
  url: http://foobar.local
assertions:
  issuers:
    - foobar
subject:
  id: some_template`),
			config: []byte(`cache_ttl: 5s`),
			assert: func(t *testing.T, err error, prototype *oauth2IntrospectionAuthenticator,
				configured *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype.r, configured.r)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.Equal(t, prototype.a, configured.a)

				assert.Nil(t, prototype.ttl)
				assert.Equal(t, 5*time.Second, *configured.ttl)
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.Equal(t, "auth2", configured.ID())
			},
		},
		{
			uc: "metadata endpoint based prototype config without cache, config with overwrites incl cache",
			id: "auth2",
			prototypeConfig: []byte(`
metadata_endpoint:
  url: http://test.com
  http_cache:
    enabled: true
    default_ttl: 10m
  disable_issuer_identifier_verification: true
`),
			config: []byte(`
assertions:
  issuers:
    - barfoo
  allowed_algorithms:
    - ES512
cache_ttl: 5s`),
			assert: func(t *testing.T, err error, prototype *oauth2IntrospectionAuthenticator,
				configured *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				// THEN
				require.NoError(t, err)

				assert.Equal(t, prototype.r, configured.r)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.a, configured.a)

				require.NoError(t, configured.a.ScopesMatcher.Match([]string{}))
				assert.Empty(t, configured.a.TargetAudiences)
				assert.ElementsMatch(t, configured.a.TrustedIssuers, []string{"barfoo"})
				assert.ElementsMatch(t, configured.a.AllowedAlgorithms, []string{string(jose.ES512)})

				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, 5*time.Second, *configured.ttl)
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())

				assert.Equal(t, "auth2", configured.ID())
			},
		},
		{
			uc: "prototype config with cache, target config with overwrites including cache",
			id: "auth2",
			prototypeConfig: []byte(`
introspection_endpoint:
  url: http://foobar.local
assertions:
  issuers:
    - foobar
subject:
  id: some_template
cache_ttl: 5s`),
			config: []byte(`
assertions:
  issuers:
    - barfoo
cache_ttl: 15s
`),
			assert: func(t *testing.T, err error, prototype *oauth2IntrospectionAuthenticator,
				configured *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, fmt.Sprintf("%v", prototype.r), fmt.Sprintf("%v", configured.r))
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.a, configured.a)
				assert.ElementsMatch(t, configured.a.TrustedIssuers, []string{"barfoo"})

				assert.Equal(t, 5*time.Second, *prototype.ttl)
				assert.Equal(t, 15*time.Second, *configured.ttl)
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.Equal(t, "auth2", configured.ID())
			},
		},
		{
			uc: "prototype config with defaults, target config with fallback on error enabled",
			id: "auth2",
			prototypeConfig: []byte(`
introspection_endpoint:
  url: http://foobar.local
assertions:
  issuers:
    - foobar
subject:
  id: some_template`),
			config: []byte(`allow_fallback_on_error: true`),
			assert: func(t *testing.T, err error, prototype *oauth2IntrospectionAuthenticator,
				configured *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, fmt.Sprintf("%v", prototype.r), fmt.Sprintf("%v", configured.r))
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.Equal(t, prototype.a, configured.a)

				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.NotEqual(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.True(t, configured.IsFallbackOnErrorAllowed())
				assert.Equal(t, "auth2", configured.ID())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newOAuth2IntrospectionAuthenticator(tc.id, pc)
			require.NoError(t, err)

			// WHEN
			auth, err := prototype.WithConfig(conf)

			// THEN
			var (
				oaia *oauth2IntrospectionAuthenticator
				ok   bool
			)

			if err == nil {
				oaia, ok = auth.(*oauth2IntrospectionAuthenticator)
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, oaia)
		})
	}
}

func TestOauth2IntrospectionAuthenticatorExecute(t *testing.T) {
	t.Parallel()

	type HandlerIdentifier interface {
		ID() string
	}

	var (
		introspectionEndpointCalled      bool
		checkIntrospectionRequest        func(req *http.Request)
		introspectionResponseContentType string
		introspectionResponseContent     []byte
		introspectionResponseCode        int

		metadataEndpointCalled      bool
		checkMetadataRequest        func(req *http.Request)
		metadataResponseContentType string
		metadataResponseContent     []byte
		metadataResponseCode        int
	)

	zeroTTL := time.Duration(0)
	jwtToken := "eyJhbGciOiJFUzM4NCIsImtpZCI6ImtleV93aXRob3V0X2NlcnQiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsiYmFyIl0sImV4cCI6MTcwMzA2NDY4MSwiaWF0IjoxNzAzMDY0NjIwLCJpc3MiOiJmb29iYXIiLCJqdGkiOiJmb28iLCJuYmYiOjE3MDMwNjQ2MjAsInNjcCI6WyJmb28iLCJiYXIiXSwic3ViIjoiZm9vIn0.ZAvLLyWR-vj3KbdS6eg-lfVbzlaME5sg55XuUaHNsfkf1t9lHf9X07IuR27x8tQuFDGq1t5LUn01NRVjAGGAu-pBIN-aDI7DgaAThZWz5VXKN-bqH55T5H6J6Z4jIk-n" //nolint:gosec

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		introspectionEndpointCalled = true

		checkIntrospectionRequest(r)

		if introspectionResponseContent != nil {
			w.Header().Set("Content-Type", introspectionResponseContentType)
			_, err := w.Write(introspectionResponseContent)
			require.NoError(t, err)
		}

		w.WriteHeader(introspectionResponseCode)
	}))

	oidcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadataEndpointCalled = true

		checkMetadataRequest(r)

		if metadataResponseContent != nil {
			w.Header().Set("Content-Type", metadataResponseContentType)
			_, err := w.Write(metadataResponseContent)
			require.NoError(t, err)
		}

		w.WriteHeader(metadataResponseCode)
	}))

	defer srv.Close()
	defer oidcSrv.Close()

	for _, tc := range []struct {
		uc             string
		authenticator  *oauth2IntrospectionAuthenticator
		instructServer func(t *testing.T)
		configureMocks func(t *testing.T,
			ctx *heimdallmocks.ContextMock,
			cch *mocks.CacheMock,
			ads *mocks2.AuthDataExtractStrategyMock,
			auth *oauth2IntrospectionAuthenticator)
		assert func(t *testing.T, err error, sub *subject.Subject)
	}{
		{
			uc:            "with failing auth data source",
			authenticator: &oauth2IntrospectionAuthenticator{id: "auth3"},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("", heimdall.ErrCommunicationTimeout)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, introspectionEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "no access token")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "with disabled cache and endpoint communication error (dns)",
			authenticator: &oauth2IntrospectionAuthenticator{
				id: "auth3",
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{IntrospectionEndpoint: &endpoint.Endpoint{URL: "http://introspection.heimdall.test.local"}}, nil
				}),
				ttl: &zeroTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("test_access_token", nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "introspection endpoint failed")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "with disabled cache and unexpected response code from the endpoint",
			authenticator: &oauth2IntrospectionAuthenticator{
				id: "auth3",
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{IntrospectionEndpoint: &endpoint.Endpoint{URL: srv.URL}}, nil
				}),
				ttl: &zeroTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("test_access_token", nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				introspectionResponseCode = http.StatusInternalServerError
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, introspectionEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "unexpected response code")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "with disabled cache and unexpected response code from the metadata endpoint",
			authenticator: &oauth2IntrospectionAuthenticator{
				id:  "auth3",
				r:   &oauth2.MetadataEndpoint{Endpoint: endpoint.Endpoint{URL: oidcSrv.URL}},
				ttl: &zeroTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("test_access_token", nil)
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				metadataResponseCode = http.StatusInternalServerError
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "unexpected response code")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "with disabled cache and failing unmarshalling of the introspection service response",
			authenticator: &oauth2IntrospectionAuthenticator{
				id: "auth3",
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						IntrospectionEndpoint: &endpoint.Endpoint{
							URL:    srv.URL,
							Method: http.MethodPost,
							Headers: map[string]string{
								"Content-Type": "application/x-www-form-urlencoded",
								"Accept":       "application/json",
							},
						},
					}, nil
				}),
				ttl: &zeroTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("test_access_token", nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkIntrospectionRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, http.MethodPost, req.Method)

					require.NoError(t, req.ParseForm())
					require.Len(t, req.Form, 2)
					assert.Equal(t, "access_token", req.Form.Get("token_type_hint"))
					assert.Equal(t, "test_access_token", req.Form.Get("token"))
				}

				introspectionResponseContentType = "text/string"
				introspectionResponseContent = []byte(`Hi foo`)
				introspectionResponseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, introspectionEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "received introspection response")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "with disabled cache and failing response validation (token not active)",
			authenticator: &oauth2IntrospectionAuthenticator{
				id: "auth3",
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						IntrospectionEndpoint: &endpoint.Endpoint{
							URL:    srv.URL,
							Method: http.MethodPost,
							Headers: map[string]string{
								"Content-Type": "application/x-www-form-urlencoded",
								"Accept":       "application/json",
							},
						},
					}, nil
				}),
				a:   oauth2.Expectation{TrustedIssuers: []string{"foobar"}},
				ttl: &zeroTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("test_access_token", nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkIntrospectionRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, http.MethodPost, req.Method)

					require.NoError(t, req.ParseForm())
					assert.Len(t, req.Form, 2)
					assert.Equal(t, "access_token", req.Form.Get("token_type_hint"))
					assert.Equal(t, "test_access_token", req.Form.Get("token"))
				}

				rawIntrospectResponse, err := json.Marshal(map[string]any{"active": false})
				require.NoError(t, err)

				introspectionResponseContentType = "application/json"
				introspectionResponseContent = rawIntrospectResponse
				introspectionResponseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, introspectionEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "assertion conditions")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "with disabled cache and failing response validation (issuer not trusted)",
			authenticator: &oauth2IntrospectionAuthenticator{
				id: "auth3",
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						IntrospectionEndpoint: &endpoint.Endpoint{
							URL:    srv.URL,
							Method: http.MethodPost,
							Headers: map[string]string{
								"Content-Type": "application/x-www-form-urlencoded",
								"Accept":       "application/json",
							},
						},
					}, nil
				}),
				a:   oauth2.Expectation{TrustedIssuers: []string{"barfoo"}},
				ttl: &zeroTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("test_access_token", nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkIntrospectionRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, http.MethodPost, req.Method)

					require.NoError(t, req.ParseForm())
					assert.Len(t, req.Form, 2)
					assert.Equal(t, "access_token", req.Form.Get("token_type_hint"))
					assert.Equal(t, "test_access_token", req.Form.Get("token"))
				}

				rawIntrospectResponse, err := json.Marshal(map[string]any{
					"active":     true,
					"scope":      "foo bar",
					"username":   "unknown",
					"token_type": "Bearer",
					"aud":        "bar",
					"sub":        "foo",
					"iss":        "foobar",
					"iat":        time.Now().Unix(),
					"nbf":        time.Now().Unix(),
					"exp":        time.Now().Unix() + 30,
				})
				require.NoError(t, err)

				introspectionResponseContentType = "application/json"
				introspectionResponseContent = rawIntrospectResponse
				introspectionResponseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, introspectionEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "assertion conditions")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "with configured issuer taking precedence over the one resolved via metadata",
			authenticator: &oauth2IntrospectionAuthenticator{
				id: "auth3",
				r: &oauth2.MetadataEndpoint{
					Endpoint: endpoint.Endpoint{
						URL:       oidcSrv.URL,
						HTTPCache: &endpoint.HTTPCache{Enabled: false},
					},
					DisableIssuerIdentifierVerification: true,
				},
				a:   oauth2.Expectation{TrustedIssuers: []string{"barfoo"}},
				ttl: &zeroTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("test_access_token", nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkIntrospectionRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, http.MethodPost, req.Method)

					require.NoError(t, req.ParseForm())
					assert.Len(t, req.Form, 2)
					assert.Equal(t, "access_token", req.Form.Get("token_type_hint"))
					assert.Equal(t, "test_access_token", req.Form.Get("token"))
				}

				rawIntrospectResponse, err := json.Marshal(map[string]any{
					"active":     true,
					"scope":      "foo bar",
					"username":   "unknown",
					"token_type": "Bearer",
					"aud":        "bar",
					"sub":        "foo",
					"iss":        "foobar",
					"iat":        time.Now().Unix(),
					"nbf":        time.Now().Unix(),
					"exp":        time.Now().Unix() + 30,
				})
				require.NoError(t, err)

				introspectionResponseContentType = "application/json"
				introspectionResponseContent = rawIntrospectResponse
				introspectionResponseCode = http.StatusOK

				checkMetadataRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, http.MethodGet, req.Method)
				}

				metadataResponseContentType = "application/json"
				metadataResponseContent, err = json.Marshal(map[string]string{
					"introspection_endpoint": srv.URL,
					"issuer":                 "foobar",
				})
				require.NoError(t, err)
				metadataResponseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, metadataEndpointCalled)
				assert.True(t, introspectionEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "issuer")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "with error while creating subject from introspection response",
			authenticator: &oauth2IntrospectionAuthenticator{
				id: "auth3",
				r: &oauth2.MetadataEndpoint{
					Endpoint: endpoint.Endpoint{
						URL:       oidcSrv.URL,
						HTTPCache: &endpoint.HTTPCache{Enabled: false},
					},
					DisableIssuerIdentifierVerification: true,
				},
				sf:  &SubjectInfo{IDFrom: "foo"},
				a:   oauth2.Expectation{ScopesMatcher: oauth2.ExactScopeStrategyMatcher{}},
				ttl: &zeroTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("test_access_token", nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkIntrospectionRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, http.MethodPost, req.Method)

					require.NoError(t, req.ParseForm())
					assert.Len(t, req.Form, 2)
					assert.Equal(t, "access_token", req.Form.Get("token_type_hint"))
					assert.Equal(t, "test_access_token", req.Form.Get("token"))
				}

				rawIntrospectResponse, err := json.Marshal(map[string]any{
					"active":     true,
					"scope":      "foo bar",
					"username":   "unknown",
					"token_type": "Bearer",
					"aud":        "bar",
					"sub":        "foo",
					"iss":        "foobar",
					"iat":        time.Now().Unix(),
					"nbf":        time.Now().Unix(),
					"exp":        time.Now().Unix() + 30,
				})
				require.NoError(t, err)

				introspectionResponseContentType = "application/json"
				introspectionResponseContent = rawIntrospectResponse
				introspectionResponseCode = http.StatusOK

				checkMetadataRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, http.MethodGet, req.Method)
				}

				metadataResponseContentType = "application/json"
				metadataResponseContent, err = json.Marshal(map[string]string{
					"introspection_endpoint": srv.URL,
					"issuer":                 "foobar",
				})
				require.NoError(t, err)
				metadataResponseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, metadataEndpointCalled)
				assert.True(t, introspectionEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to extract subject")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "with no introspection endpoint set in the metadata",
			authenticator: &oauth2IntrospectionAuthenticator{
				id: "auth3",
				r: &oauth2.MetadataEndpoint{
					Endpoint: endpoint.Endpoint{
						URL:       oidcSrv.URL,
						HTTPCache: &endpoint.HTTPCache{Enabled: false},
					},
					DisableIssuerIdentifierVerification: true,
				},
				sf:  &SubjectInfo{IDFrom: "foo"},
				a:   oauth2.Expectation{ScopesMatcher: oauth2.ExactScopeStrategyMatcher{}},
				ttl: &zeroTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("test_access_token", nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				var err error

				checkMetadataRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, http.MethodGet, req.Method)
				}

				metadataResponseContentType = "application/json"
				metadataResponseContent, err = json.Marshal(map[string]string{
					"issuer": "foobar",
				})
				require.NoError(t, err)
				metadataResponseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, metadataEndpointCalled)
				assert.False(t, introspectionEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "required introspection_endpoint")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "with disabled cache and template error while executing introspection endpoint",
			authenticator: &oauth2IntrospectionAuthenticator{
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						IntrospectionEndpoint: &endpoint.Endpoint{
							URL:    srv.URL + "/{{ TokenIssuer }}",
							Method: http.MethodPost,
							Headers: map[string]string{
								"Content-Type": "application/x-www-form-urlencoded",
								"Accept":       "application/json",
							},
						},
					}, nil
				}),
				a: oauth2.Expectation{
					TrustedIssuers: []string{"foobar"},
					ScopesMatcher:  oauth2.ExactScopeStrategyMatcher{},
				},
				sf:  &SubjectInfo{IDFrom: "sub"},
				ttl: &zeroTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtToken, nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, introspectionEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed to render URL")
			},
		},
		{
			uc: "with disabled cache and successful execution using templated introspection endpoint",
			authenticator: &oauth2IntrospectionAuthenticator{
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						IntrospectionEndpoint: &endpoint.Endpoint{
							URL:    srv.URL + "/{{ .TokenIssuer }}",
							Method: http.MethodPost,
							Headers: map[string]string{
								"Content-Type": "application/x-www-form-urlencoded",
								"Accept":       "application/json",
							},
						},
					}, nil
				}),
				a: oauth2.Expectation{
					TrustedIssuers: []string{"foobar"},
					ScopesMatcher:  oauth2.ExactScopeStrategyMatcher{},
				},
				sf:  &SubjectInfo{IDFrom: "sub"},
				ttl: &zeroTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtToken, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkIntrospectionRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, http.MethodPost, req.Method)
					assert.Equal(t, "/foobar", req.URL.Path)

					require.NoError(t, req.ParseForm())
					assert.Len(t, req.Form, 2)
					assert.Equal(t, "access_token", req.Form.Get("token_type_hint"))
					assert.Equal(t, jwtToken, req.Form.Get("token"))
				}

				rawIntrospectResponse, err := json.Marshal(map[string]any{
					"active":     true,
					"scope":      "foo bar",
					"username":   "unknown",
					"token_type": "Bearer",
					"aud":        "bar",
					"sub":        "foo",
					"iss":        "foobar",
					"iat":        time.Now().Unix(),
					"nbf":        time.Now().Unix(),
					"exp":        time.Now().Unix() + 30,
				})
				require.NoError(t, err)

				introspectionResponseContentType = "application/json"
				introspectionResponseContent = rawIntrospectResponse
				introspectionResponseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, introspectionEndpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "foo", sub.ID)
				require.Len(t, sub.Attributes, 10)
				assert.Equal(t, "foo bar", sub.Attributes["scope"])
				assert.Equal(t, true, sub.Attributes["active"]) //nolint:testifylint
				assert.Equal(t, "unknown", sub.Attributes["username"])
				assert.Equal(t, "foobar", sub.Attributes["iss"])
				assert.Equal(t, "bar", sub.Attributes["aud"])
				assert.Equal(t, "Bearer", sub.Attributes["token_type"])
				assert.NotEmpty(t, sub.Attributes["nbf"])
				assert.NotEmpty(t, sub.Attributes["iat"])
				assert.NotEmpty(t, sub.Attributes["exp"])
			},
		},
		{
			uc: "with disabled cache and successful execution using templated metadata endpoint",
			authenticator: &oauth2IntrospectionAuthenticator{
				r:   &oauth2.MetadataEndpoint{Endpoint: endpoint.Endpoint{URL: oidcSrv.URL + "/{{ .TokenIssuer }}"}},
				a:   oauth2.Expectation{ScopesMatcher: oauth2.ExactScopeStrategyMatcher{}},
				sf:  &SubjectInfo{IDFrom: "sub"},
				ttl: &zeroTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtToken, nil)
				// http cache
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil)
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, mock.MatchedBy(
					func(ttl time.Duration) bool { return ttl.Round(time.Minute) == 30*time.Minute },
				))
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkIntrospectionRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, http.MethodPost, req.Method)

					require.NoError(t, req.ParseForm())
					assert.Len(t, req.Form, 2)
					assert.Equal(t, "access_token", req.Form.Get("token_type_hint"))
					assert.Equal(t, jwtToken, req.Form.Get("token"))
				}
				rawIntrospectResponse, err := json.Marshal(map[string]any{
					"active":     true,
					"scope":      "foo bar",
					"username":   "unknown",
					"token_type": "Bearer",
					"aud":        "bar",
					"sub":        "foo",
					"iss":        oidcSrv.URL + "/foobar",
					"iat":        time.Now().Unix(),
					"nbf":        time.Now().Unix(),
					"exp":        time.Now().Unix() + 30,
				})
				require.NoError(t, err)

				introspectionResponseContentType = "application/json"
				introspectionResponseContent = rawIntrospectResponse
				introspectionResponseCode = http.StatusOK

				checkMetadataRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, http.MethodGet, req.Method)
					assert.Equal(t, "/foobar", req.URL.Path)
				}

				metadataResponseContentType = "application/json"
				metadataResponseContent, err = json.Marshal(map[string]string{
					"introspection_endpoint": srv.URL,
					"issuer":                 oidcSrv.URL + "/foobar",
				})
				require.NoError(t, err)
				metadataResponseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, introspectionEndpointCalled)
				assert.True(t, metadataEndpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "foo", sub.ID)
				require.Len(t, sub.Attributes, 10)
				assert.Equal(t, "foo bar", sub.Attributes["scope"])
				assert.Equal(t, true, sub.Attributes["active"]) //nolint:testifylint
				assert.Equal(t, "unknown", sub.Attributes["username"])
				assert.Equal(t, oidcSrv.URL+"/foobar", sub.Attributes["iss"])
				assert.Equal(t, "bar", sub.Attributes["aud"])
				assert.Equal(t, "Bearer", sub.Attributes["token_type"])
				assert.NotEmpty(t, sub.Attributes["nbf"])
				assert.NotEmpty(t, sub.Attributes["iat"])
				assert.NotEmpty(t, sub.Attributes["exp"])
			},
		},
		{
			uc: "with default cache, without cache hit and successful execution",
			authenticator: &oauth2IntrospectionAuthenticator{
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						IntrospectionEndpoint: &endpoint.Endpoint{
							URL:    srv.URL,
							Method: http.MethodPost,
							Headers: map[string]string{
								"Content-Type": "application/x-www-form-urlencoded",
								"Accept":       "application/json",
							},
						},
					}, nil
				}),
				a: oauth2.Expectation{
					TrustedIssuers: []string{"foobar"},
					ScopesMatcher:  oauth2.ExactScopeStrategyMatcher{},
				},
				sf: &SubjectInfo{IDFrom: "sub"},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("test_access_token", nil)
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil)
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkIntrospectionRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, http.MethodPost, req.Method)

					require.NoError(t, req.ParseForm())
					require.Len(t, req.Form, 2)
					assert.Equal(t, "access_token", req.Form.Get("token_type_hint"))
					assert.Equal(t, "test_access_token", req.Form.Get("token"))
				}

				rawIntrospectResponse, err := json.Marshal(map[string]any{
					"active":     true,
					"scope":      "foo bar",
					"username":   "unknown",
					"token_type": "Bearer",
					"aud":        "bar",
					"sub":        "foo",
					"iss":        "foobar",
					"iat":        time.Now().Unix(),
					"nbf":        time.Now().Unix(),
					"exp":        time.Now().Unix() + 30,
				})
				require.NoError(t, err)

				introspectionResponseContentType = "application/json"
				introspectionResponseContent = rawIntrospectResponse
				introspectionResponseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, introspectionEndpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "foo", sub.ID)
				require.Len(t, sub.Attributes, 10)
				assert.Equal(t, "foo bar", sub.Attributes["scope"])
				assert.Equal(t, true, sub.Attributes["active"]) //nolint:testifylint
				assert.Equal(t, "unknown", sub.Attributes["username"])
				assert.Equal(t, "foobar", sub.Attributes["iss"])
				assert.Equal(t, "bar", sub.Attributes["aud"])
				assert.Equal(t, "Bearer", sub.Attributes["token_type"])
				assert.NotEmpty(t, sub.Attributes["nbf"])
				assert.NotEmpty(t, sub.Attributes["iat"])
				assert.NotEmpty(t, sub.Attributes["exp"])
			},
		},
		{
			uc: "with default cache, with bad cache hit and successful execution",
			authenticator: &oauth2IntrospectionAuthenticator{
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						IntrospectionEndpoint: &endpoint.Endpoint{
							URL:    srv.URL,
							Method: http.MethodPost,
							Headers: map[string]string{
								"Content-Type": "application/x-www-form-urlencoded",
								"Accept":       "application/json",
							},
						},
					}, nil
				}),
				a: oauth2.Expectation{
					TrustedIssuers: []string{"foobar"},
					ScopesMatcher:  oauth2.ExactScopeStrategyMatcher{},
				},
				sf: &SubjectInfo{IDFrom: "sub"},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("test_access_token", nil)
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(zeroTTL)
				cch.EXPECT().Delete(mock.Anything, mock.Anything)
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkIntrospectionRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, http.MethodPost, req.Method)

					require.NoError(t, req.ParseForm())
					assert.Len(t, req.Form, 2)
					assert.Equal(t, "access_token", req.Form.Get("token_type_hint"))
					assert.Equal(t, "test_access_token", req.Form.Get("token"))
				}

				rawIntrospectResponse, err := json.Marshal(map[string]any{
					"active":     true,
					"scope":      "foo bar",
					"username":   "unknown",
					"token_type": "Bearer",
					"aud":        "bar",
					"sub":        "foo",
					"iss":        "foobar",
					"iat":        time.Now().Unix(),
					"nbf":        time.Now().Unix(),
					"exp":        time.Now().Unix() + 30,
				})
				require.NoError(t, err)

				introspectionResponseContentType = "application/json"
				introspectionResponseContent = rawIntrospectResponse
				introspectionResponseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, introspectionEndpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "foo", sub.ID)
				assert.Len(t, sub.Attributes, 10)
				assert.Equal(t, "foo bar", sub.Attributes["scope"])
				assert.Equal(t, true, sub.Attributes["active"]) //nolint:testifylint
				assert.Equal(t, "unknown", sub.Attributes["username"])
				assert.Equal(t, "foobar", sub.Attributes["iss"])
				assert.Equal(t, "bar", sub.Attributes["aud"])
				assert.Equal(t, "Bearer", sub.Attributes["token_type"])
				assert.NotEmpty(t, sub.Attributes["nbf"])
				assert.NotEmpty(t, sub.Attributes["iat"])
				assert.NotEmpty(t, sub.Attributes["exp"])
			},
		},
		{
			uc: "with default cache, with cache hit and successful execution",
			authenticator: &oauth2IntrospectionAuthenticator{
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						IntrospectionEndpoint: &endpoint.Endpoint{
							URL:    srv.URL,
							Method: http.MethodPost,
							Headers: map[string]string{
								"Content-Type": "application/x-www-form-urlencoded",
								"Accept":       "application/json",
							},
						},
					}, nil
				}),
				a: oauth2.Expectation{
					TrustedIssuers: []string{"foobar"},
					ScopesMatcher:  oauth2.ExactScopeStrategyMatcher{},
				},
				sf: &SubjectInfo{IDFrom: "sub"},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *oauth2IntrospectionAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("test_access_token", nil)

				rawIntrospectResponse, err := json.Marshal(map[string]any{
					"active":     true,
					"scope":      "foo bar",
					"username":   "unknown",
					"token_type": "Bearer",
					"aud":        "bar",
					"sub":        "foo",
					"iss":        "foobar",
					"iat":        time.Now().Unix(),
					"nbf":        time.Now().Unix(),
					"exp":        time.Now().Unix() + 30,
				})
				require.NoError(t, err)

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(rawIntrospectResponse)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, introspectionEndpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "foo", sub.ID)
				assert.Len(t, sub.Attributes, 10)
				assert.Equal(t, "foo bar", sub.Attributes["scope"])
				assert.Equal(t, true, sub.Attributes["active"]) //nolint:testifylint
				assert.Equal(t, "unknown", sub.Attributes["username"])
				assert.Equal(t, "foobar", sub.Attributes["iss"])
				assert.Equal(t, "bar", sub.Attributes["aud"])
				assert.Equal(t, "Bearer", sub.Attributes["token_type"])
				assert.NotEmpty(t, sub.Attributes["nbf"])
				assert.NotEmpty(t, sub.Attributes["iat"])
				assert.NotEmpty(t, sub.Attributes["exp"])
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			introspectionEndpointCalled = false
			introspectionResponseContentType = ""
			introspectionResponseContent = nil

			metadataEndpointCalled = false
			metadataResponseContentType = ""
			metadataResponseContent = nil

			checkIntrospectionRequest = func(*http.Request) { t.Helper() }
			checkMetadataRequest = func(*http.Request) { t.Helper() }

			instructServer := x.IfThenElse(tc.instructServer != nil,
				tc.instructServer,
				func(t *testing.T) { t.Helper() })

			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T,
					_ *heimdallmocks.ContextMock,
					_ *mocks.CacheMock,
					_ *mocks2.AuthDataExtractStrategyMock,
					_ *oauth2IntrospectionAuthenticator,
				) {
					t.Helper()
				})

			ads := mocks2.NewAuthDataExtractStrategyMock(t)
			tc.authenticator.ads = ads

			cch := mocks.NewCacheMock(t)

			ctx := heimdallmocks.NewContextMock(t)
			ctx.EXPECT().AppContext().Return(cache.WithContext(context.Background(), cch))

			configureMocks(t, ctx, cch, ads, tc.authenticator)
			instructServer(t)

			// WHEN
			sub, err := tc.authenticator.Execute(ctx)

			// THEN
			tc.assert(t, err, sub)
		})
	}
}

func TestCacheTTLCalculation(t *testing.T) {
	t.Parallel()

	negativeTTL := -1 * time.Second
	zeroTTL := 0 * time.Second
	positiveSmallTTL := 10 * time.Second
	positiveBigTTL := 10 * time.Minute

	for _, tc := range []struct {
		uc            string
		authenticator *oauth2IntrospectionAuthenticator
		response      func() *oauth2.IntrospectionResponse
		assert        func(t *testing.T, ttl time.Duration)
	}{
		{
			uc:            "default (nil) ttl settings and no exp in response",
			authenticator: &oauth2IntrospectionAuthenticator{},
			response:      func() *oauth2.IntrospectionResponse { return &oauth2.IntrospectionResponse{} },
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, zeroTTL, ttl)
			},
		},
		{
			uc:            "default (nil) ttl settings and exp in response which would result in negative ttl with 10s leeway",
			authenticator: &oauth2IntrospectionAuthenticator{},
			response: func() *oauth2.IntrospectionResponse {
				expiry := oauth2.NumericDate(time.Now().Add(8 * time.Second).Unix())
				resp := &oauth2.IntrospectionResponse{}
				resp.Expiry = &expiry

				return resp
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, zeroTTL, ttl)
			},
		},
		{
			uc:            "default (nil) ttl settings and exp in response which would result in 0 ttl with 10s leeway",
			authenticator: &oauth2IntrospectionAuthenticator{},
			response: func() *oauth2.IntrospectionResponse {
				expiry := oauth2.NumericDate(time.Now().Add(10 * time.Second).Unix())
				resp := &oauth2.IntrospectionResponse{}
				resp.Expiry = &expiry

				return resp
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, zeroTTL, ttl)
			},
		},
		{
			uc:            "default (nil) ttl settings and exp in response which would result in positive ttl with 10s leeway",
			authenticator: &oauth2IntrospectionAuthenticator{},
			response: func() *oauth2.IntrospectionResponse {
				expiry := oauth2.NumericDate(time.Now().Add(12 * time.Second).Unix())
				resp := &oauth2.IntrospectionResponse{}
				resp.Expiry = &expiry

				return resp
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, 2*time.Second, ttl)
			},
		},
		{
			uc:            "negative ttl settings and exp not set in response",
			authenticator: &oauth2IntrospectionAuthenticator{ttl: &negativeTTL},
			response:      func() *oauth2.IntrospectionResponse { return &oauth2.IntrospectionResponse{} },
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, zeroTTL, ttl)
			},
		},
		{
			uc:            "zero ttl settings and exp not set in response",
			authenticator: &oauth2IntrospectionAuthenticator{ttl: &zeroTTL},
			response:      func() *oauth2.IntrospectionResponse { return &oauth2.IntrospectionResponse{} },
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, zeroTTL, ttl)
			},
		},
		{
			uc:            "positive ttl settings and exp not set in response",
			authenticator: &oauth2IntrospectionAuthenticator{ttl: &positiveSmallTTL},
			response:      func() *oauth2.IntrospectionResponse { return &oauth2.IntrospectionResponse{} },
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, positiveSmallTTL, ttl)
			},
		},
		{
			uc:            "negative ttl settings and exp set to a value response, which would result in positive ttl with 10s leeway",
			authenticator: &oauth2IntrospectionAuthenticator{ttl: &negativeTTL},
			response: func() *oauth2.IntrospectionResponse {
				expiry := oauth2.NumericDate(time.Now().Add(15 * time.Second).Unix())
				resp := &oauth2.IntrospectionResponse{}
				resp.Expiry = &expiry

				return resp
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, zeroTTL, ttl)
			},
		},
		{
			uc:            "zero ttl settings and exp set to a value response, which would result in 0s ttl with 10s leeway",
			authenticator: &oauth2IntrospectionAuthenticator{ttl: &negativeTTL},
			response: func() *oauth2.IntrospectionResponse {
				expiry := oauth2.NumericDate(time.Now().Add(10 * time.Second).Unix())
				resp := &oauth2.IntrospectionResponse{}
				resp.Expiry = &expiry

				return resp
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, zeroTTL, ttl)
			},
		},
		{
			uc:            "zero ttl settings and exp set to a value response, which would result in positive ttl with 10s leeway",
			authenticator: &oauth2IntrospectionAuthenticator{ttl: &negativeTTL},
			response: func() *oauth2.IntrospectionResponse {
				expiry := oauth2.NumericDate(time.Now().Add(12 * time.Second).Unix())
				resp := &oauth2.IntrospectionResponse{}
				resp.Expiry = &expiry

				return resp
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, zeroTTL, ttl)
			},
		},
		{
			uc:            "ttl settings smaller compared to ttl calculation on exp set in response",
			authenticator: &oauth2IntrospectionAuthenticator{ttl: &positiveSmallTTL},
			response: func() *oauth2.IntrospectionResponse {
				expiry := oauth2.NumericDate(time.Now().Add(12 * time.Minute).Unix())
				resp := &oauth2.IntrospectionResponse{}
				resp.Expiry = &expiry

				return resp
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, positiveSmallTTL, ttl)
			},
		},
		{
			uc:            "ttl settings bigger compared to ttl calculation on exp set in response",
			authenticator: &oauth2IntrospectionAuthenticator{ttl: &positiveBigTTL},
			response: func() *oauth2.IntrospectionResponse {
				expiry := oauth2.NumericDate(time.Now().Add(15 * time.Second).Unix())
				resp := &oauth2.IntrospectionResponse{}
				resp.Expiry = &expiry

				return resp
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, 5*time.Second, ttl)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			ttl := tc.authenticator.getCacheTTL(tc.response())

			// THEN
			tc.assert(t, ttl)
		})
	}
}
