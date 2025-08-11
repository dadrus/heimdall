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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	heimdallmocks "github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/rules/endpoint/authstrategy"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
	mocks2 "github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/oauth2"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/oauth2/clientcredentials"
	"github.com/dadrus/heimdall/internal/truststore"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

const (
	kidKeyWithoutCert = "key_without_cert"
	kidKeyWithCert    = "key_with_cert"
	kidRSAKey         = "key_rsa"
)

func TestJwtAuthenticatorCreate(t *testing.T) {
	t.Parallel()

	// ROOT CAs
	rootCA1, err := testsupport.NewRootCA("Test Root CA 1", time.Hour*24)
	require.NoError(t, err)

	pemBytes, err := pemx.BuildPEM(pemx.WithX509Certificate(rootCA1.Certificate))
	require.NoError(t, err)

	file, err := os.CreateTemp(t.TempDir(), "test-create-jwt-authenticator-*")
	require.NoError(t, err)

	_, err = file.Write(pemBytes)
	require.NoError(t, err)

	trustStorePath := file.Name()

	for uc, tc := range map[string]struct {
		enforceTLS bool
		config     []byte
		assert     func(t *testing.T, err error, a *jwtAuthenticator)
	}{
		"unsupported fields": {
			config: []byte(`
jwt_source:
  - header: foo-header
foo: bar
`),
			assert: func(t *testing.T, err error, _ *jwtAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"missing url config": {
			config: []byte(`
jwt_source:
  - header: foo-header
assertions:
  issuers:
    - foobar
subject:
  id: some_template`),
			assert: func(t *testing.T, err error, _ *jwtAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'jwks_endpoint' is a required field")
			},
		},
		"missing trusted_issuers for jwks endpoint based configuration": {
			config: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  audience:
    - foobar
subject:
  id: some_template`),
			assert: func(t *testing.T, err error, _ *jwtAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'issuers' is a required field")
			},
		},
		"minimal jwks endpoint based configuration with malformed jwks endpoint": {
			config: []byte(`
jwks_endpoint:
  url: "{{ .IssuerName }}"
assertions:
  issuers:
    - foobar`),
			assert: func(t *testing.T, err error, _ *jwtAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'jwks_endpoint'.'url' must be a valid URL")
			},
		},
		"minimal jwks endpoint based configuration with defaults, without cache and TLS enforcement": {
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
				_, ok := auth.r.(oauth2.ResolverAdapterFunc)
				require.True(t, ok)
				md, err := auth.r.Get(t.Context(), nil)
				require.NoError(t, err)
				assert.Equal(t, "http://test.com", md.JWKSEndpoint.URL)
				assert.Equal(t, http.MethodGet, md.JWKSEndpoint.Method)
				assert.Len(t, md.JWKSEndpoint.Headers, 1)
				assert.Contains(t, md.JWKSEndpoint.Headers, "Accept")
				assert.Equal(t, "application/json", md.JWKSEndpoint.Headers["Accept"])

				// token extractor settings
				assert.IsType(t, extractors.CompositeExtractStrategy{}, auth.ads)
				assert.Len(t, auth.ads, 3)
				assert.Contains(t, auth.ads, extractors.HeaderValueExtractStrategy{Name: "Authorization", Scheme: "Bearer"})
				assert.Contains(t, auth.ads, extractors.QueryParameterExtractStrategy{Name: "access_token"})
				assert.Contains(t, auth.ads, extractors.BodyParameterExtractStrategy{Name: "access_token"})

				// assertions settings
				require.NoError(t, auth.a.ScopesMatcher.Match([]string{}))
				assert.Empty(t, auth.a.Audiences)
				assert.Len(t, auth.a.TrustedIssuers, 1)
				assert.Contains(t, auth.a.TrustedIssuers, "foobar")
				assert.Len(t, auth.a.AllowedAlgorithms, 6)

				assert.ElementsMatch(t, auth.a.AllowedAlgorithms, []string{
					string(jose.ES256), string(jose.ES384), string(jose.ES512),
					string(jose.PS256), string(jose.PS384), string(jose.PS512),
				})
				assert.Equal(t, time.Duration(0), auth.a.ValidityLeeway)

				// subject settings
				sess, ok := auth.sf.(*SubjectInfo)
				require.True(t, ok)
				assert.Equal(t, "sub", sess.IDFrom)
				assert.Empty(t, sess.AttributesFrom)

				// cache settings
				assert.Nil(t, auth.ttl)

				// jwk validation settings
				assert.True(t, auth.validateJWKCert)
				assert.Empty(t, auth.trustStore)

				// handler id
				assert.Equal(t, auth.Name(), auth.ID())
				assert.Equal(t, "minimal jwks endpoint based configuration with defaults, without cache and TLS enforcement", auth.ID())
			},
		},
		"minimal jwks endpoint based configuration with cache and TLS enforcement": {
			enforceTLS: true,
			config: []byte(`
jwks_endpoint:
  url: https://test.com
assertions:
  issuers:
    - foobar
cache_ttl: 5s`),
			assert: func(t *testing.T, err error, auth *jwtAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				// endpoint settings
				_, ok := auth.r.(oauth2.ResolverAdapterFunc)
				require.True(t, ok)
				md, err := auth.r.Get(t.Context(), nil)
				require.NoError(t, err)
				assert.Equal(t, "https://test.com", md.JWKSEndpoint.URL)
				assert.Equal(t, http.MethodGet, md.JWKSEndpoint.Method)
				assert.Len(t, md.JWKSEndpoint.Headers, 1)
				assert.Contains(t, md.JWKSEndpoint.Headers, "Accept")
				assert.Equal(t, "application/json", md.JWKSEndpoint.Headers["Accept"])

				// token extractor settings
				assert.IsType(t, extractors.CompositeExtractStrategy{}, auth.ads)
				assert.Len(t, auth.ads, 3)
				assert.Contains(t, auth.ads, extractors.HeaderValueExtractStrategy{Name: "Authorization", Scheme: "Bearer"})
				assert.Contains(t, auth.ads, extractors.QueryParameterExtractStrategy{Name: "access_token"})
				assert.Contains(t, auth.ads, extractors.BodyParameterExtractStrategy{Name: "access_token"})

				// assertions settings
				require.NoError(t, auth.a.ScopesMatcher.Match([]string{}))
				assert.Empty(t, auth.a.Audiences)
				assert.Len(t, auth.a.TrustedIssuers, 1)
				assert.Contains(t, auth.a.TrustedIssuers, "foobar")
				assert.Len(t, auth.a.AllowedAlgorithms, 6)

				assert.ElementsMatch(t, auth.a.AllowedAlgorithms, []string{
					string(jose.ES256), string(jose.ES384), string(jose.ES512),
					string(jose.PS256), string(jose.PS384), string(jose.PS512),
				})
				assert.Equal(t, time.Duration(0), auth.a.ValidityLeeway)

				// subject settings
				sess, ok := auth.sf.(*SubjectInfo)
				require.True(t, ok)
				assert.Equal(t, "sub", sess.IDFrom)
				assert.Empty(t, sess.AttributesFrom)

				// cache settings
				assert.NotNil(t, auth.ttl)
				assert.Equal(t, 5*time.Second, *auth.ttl)

				// jwk validation settings
				assert.True(t, auth.validateJWKCert)
				assert.Empty(t, auth.trustStore)

				// handler id
				assert.Equal(t, auth.Name(), auth.ID())
				assert.Equal(t, "minimal jwks endpoint based configuration with cache and TLS enforcement", auth.ID())
			},
		},
		"minimal jwks endpoint based configuration with enforced but disabled TLS": {
			enforceTLS: true,
			config: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  issuers:
    - foobar`),
			assert: func(t *testing.T, err error, _ *jwtAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'jwks_endpoint'.'url' scheme must be https")
			},
		},
		"valid configuration with overwrites, without cache": {
			config: []byte(`
jwks_endpoint:
  url: http://test.com
  method: POST
  headers:
    Accept: application/foobar
jwt_source:
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
allow_fallback_on_error: true
validate_jwk: false
trust_store: ` + trustStorePath),
			assert: func(t *testing.T, err error, auth *jwtAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				// endpoint settings
				_, ok := auth.r.(oauth2.ResolverAdapterFunc)
				require.True(t, ok)
				md, err := auth.r.Get(t.Context(), nil)
				require.NoError(t, err)
				assert.Equal(t, "http://test.com", md.JWKSEndpoint.URL)
				assert.Equal(t, "POST", md.JWKSEndpoint.Method)
				assert.Len(t, md.JWKSEndpoint.Headers, 1)
				assert.Contains(t, md.JWKSEndpoint.Headers, "Accept")
				assert.Equal(t, "application/foobar", md.JWKSEndpoint.Headers["Accept"])

				// token extractor settings
				assert.IsType(t, extractors.CompositeExtractStrategy{}, auth.ads)
				assert.Len(t, auth.ads, 3)
				assert.Contains(t, auth.ads, &extractors.HeaderValueExtractStrategy{
					Name: "foo-header", Scheme: "foo",
				})
				assert.Contains(t, auth.ads, &extractors.QueryParameterExtractStrategy{Name: "foo_query_param"})
				assert.Contains(t, auth.ads, &extractors.BodyParameterExtractStrategy{Name: "foo_body_param"})

				// assertions settings
				assert.NotNil(t, auth.a.ScopesMatcher)
				require.NoError(t, auth.a.ScopesMatcher.Match([]string{"foo"}))
				assert.Empty(t, auth.a.Audiences)
				assert.Len(t, auth.a.TrustedIssuers, 1)
				assert.Contains(t, auth.a.TrustedIssuers, "foobar")
				assert.Len(t, auth.a.AllowedAlgorithms, 1)

				assert.ElementsMatch(t, auth.a.AllowedAlgorithms, []string{string(jose.ES256)})
				assert.Equal(t, time.Duration(0), auth.a.ValidityLeeway)

				// subject settings
				sess, ok := auth.sf.(*SubjectInfo)
				require.True(t, ok)
				assert.Equal(t, "some_claim", sess.IDFrom)
				assert.Empty(t, sess.AttributesFrom)

				// cache settings
				assert.Nil(t, auth.ttl)

				// jwk validation settings
				assert.False(t, auth.validateJWKCert)
				assert.Contains(t, auth.trustStore, rootCA1.Certificate)

				// handler id
				assert.Equal(t, auth.Name(), auth.ID())
				assert.Equal(t, "valid configuration with overwrites, without cache", auth.ID())
			},
		},
		"minimal metadata endpoint based configuration with malformed endpoint": {
			config: []byte(`
metadata_endpoint:
  url: "{{ .IssuerName }}"
`),
			assert: func(t *testing.T, err error, _ *jwtAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'metadata_endpoint'.'url' must be a valid URL")
			},
		},
		"minimal metadata endpoint based configuration with enforced but disabled TLS": {
			enforceTLS: true,
			config: []byte(`
metadata_endpoint:
  url: http://test.com
`),
			assert: func(t *testing.T, err error, _ *jwtAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'metadata_endpoint'.'url' scheme must be https")
			},
		},
		"metadata endpoint based configuration with cache and enabled TLS enforcement": {
			enforceTLS: true,
			config: []byte(`
metadata_endpoint:
  url: https://test.com
  disable_issuer_identifier_verification: true
cache_ttl: 5s`),
			assert: func(t *testing.T, err error, auth *jwtAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				// endpoint settings
				_, ok := auth.r.(oauth2.ResolverAdapterFunc)
				require.False(t, ok)

				// token extractor settings
				assert.IsType(t, extractors.CompositeExtractStrategy{}, auth.ads)
				assert.Len(t, auth.ads, 3)
				assert.Contains(t, auth.ads, extractors.HeaderValueExtractStrategy{Name: "Authorization", Scheme: "Bearer"})
				assert.Contains(t, auth.ads, extractors.QueryParameterExtractStrategy{Name: "access_token"})
				assert.Contains(t, auth.ads, extractors.BodyParameterExtractStrategy{Name: "access_token"})

				// assertions settings
				require.NoError(t, auth.a.ScopesMatcher.Match([]string{}))
				assert.Empty(t, auth.a.Audiences)
				assert.Empty(t, auth.a.TrustedIssuers)
				assert.Len(t, auth.a.AllowedAlgorithms, 6)
				assert.ElementsMatch(t, auth.a.AllowedAlgorithms, []string{
					string(jose.ES256), string(jose.ES384), string(jose.ES512),
					string(jose.PS256), string(jose.PS384), string(jose.PS512),
				})
				assert.Equal(t, time.Duration(0), auth.a.ValidityLeeway)

				// subject settings
				sess, ok := auth.sf.(*SubjectInfo)
				require.True(t, ok)
				assert.Equal(t, "sub", sess.IDFrom)
				assert.Empty(t, sess.AttributesFrom)

				// cache settings
				assert.NotNil(t, auth.ttl)
				assert.Equal(t, 5*time.Second, *auth.ttl)

				// jwk validation settings
				assert.True(t, auth.validateJWKCert)
				assert.Empty(t, auth.trustStore)

				// handler id
				assert.Equal(t, auth.Name(), auth.ID())
				assert.Equal(t, "metadata endpoint based configuration with cache and enabled TLS enforcement", auth.ID())
			},
		},
		"metadata endpoint with resolved endpoints configuration and enabled TLS enforcement": {
			enforceTLS: true,
			config: []byte(`
metadata_endpoint:
  url: https://test.com
  resolved_endpoints:
    jwks_uri:
      auth:
        type: oauth2_client_credentials
        config:
          token_url: https://example.com/token
          client_id: foo
          client_secret: bar
      retry:
        give_up_after: 1m
        max_delay: 5s
      http_cache:
        enabled: true
        default_ttl: 10m
cache_ttl: 5s`),
			assert: func(t *testing.T, err error, auth *jwtAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				// endpoint settings
				mdep, ok := auth.r.(*oauth2.MetadataEndpoint)
				require.True(t, ok)

				assert.Equal(t, "https://test.com", mdep.URL)
				require.Len(t, mdep.ResolvedEndpoints, 1)
				reps, ok := mdep.ResolvedEndpoints["jwks_uri"]
				require.True(t, ok)
				assert.Equal(t, &endpoint.HTTPCache{
					Enabled:    true,
					DefaultTTL: 10 * time.Minute,
				}, reps.HTTPCache)
				assert.Equal(t, &endpoint.Retry{
					GiveUpAfter: 1 * time.Minute,
					MaxDelay:    5 * time.Second,
				}, reps.Retry)
				assert.Equal(t, &authstrategy.OAuth2ClientCredentials{
					Config: clientcredentials.Config{
						TokenURL:     "https://example.com/token",
						ClientID:     "foo",
						ClientSecret: "bar",
					},
				}, reps.AuthStrategy)

				// token extractor settings
				assert.IsType(t, extractors.CompositeExtractStrategy{}, auth.ads)
				assert.Len(t, auth.ads, 3)
				assert.Contains(t, auth.ads, extractors.HeaderValueExtractStrategy{Name: "Authorization", Scheme: "Bearer"})
				assert.Contains(t, auth.ads, extractors.QueryParameterExtractStrategy{Name: "access_token"})
				assert.Contains(t, auth.ads, extractors.BodyParameterExtractStrategy{Name: "access_token"})

				// assertions settings
				require.NoError(t, auth.a.ScopesMatcher.Match([]string{}))
				assert.Empty(t, auth.a.Audiences)
				assert.Empty(t, auth.a.TrustedIssuers)
				assert.Len(t, auth.a.AllowedAlgorithms, 6)
				assert.ElementsMatch(t, auth.a.AllowedAlgorithms, []string{
					string(jose.ES256), string(jose.ES384), string(jose.ES512),
					string(jose.PS256), string(jose.PS384), string(jose.PS512),
				})
				assert.Equal(t, time.Duration(0), auth.a.ValidityLeeway)

				// subject settings
				sess, ok := auth.sf.(*SubjectInfo)
				require.True(t, ok)
				assert.Equal(t, "sub", sess.IDFrom)
				assert.Empty(t, sess.AttributesFrom)

				// cache settings
				assert.NotNil(t, auth.ttl)
				assert.Equal(t, 5*time.Second, *auth.ttl)

				// jwk validation settings
				assert.True(t, auth.validateJWKCert)
				assert.Empty(t, auth.trustStore)

				// handler id
				assert.Equal(t, auth.Name(), auth.ID())
				assert.Equal(t, "metadata endpoint with resolved endpoints configuration and enabled TLS enforcement", auth.ID())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			es := config.EnforcementSettings{EnforceEgressTLS: tc.enforceTLS}
			validator, err := validation.NewValidator(
				validation.WithTagValidator(es),
				validation.WithErrorTranslator(es),
			)
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			// WHEN
			a, err := newJwtAuthenticator(appCtx, uc, conf)

			// THEN
			tc.assert(t, err, a)
		})
	}
}

func TestJwtAuthenticatorWithConfig(t *testing.T) {
	t.Parallel()

	// ROOT CAs
	rootCA1, err := testsupport.NewRootCA("Test Root CA 1", time.Hour*24)
	require.NoError(t, err)

	pemBytes, err := pemx.BuildPEM(pemx.WithX509Certificate(rootCA1.Certificate))
	require.NoError(t, err)

	file, err := os.CreateTemp(t.TempDir(), "test-create-jwt-authenticator-from-prototype-*")
	require.NoError(t, err)

	_, err = file.Write(pemBytes)
	require.NoError(t, err)

	trustStorePath := file.Name()

	for uc, tc := range map[string]struct {
		prototypeConfig []byte
		config          []byte
		stepID          string
		assert          func(t *testing.T, err error, prototype *jwtAuthenticator, configured *jwtAuthenticator)
	}{
		"using empty target config and step ID": {
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
		"using empty target config and step ID configured": {
			prototypeConfig: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  issuers:
    - foobar
cache_ttl: 5s`),
			stepID: "foo",
			assert: func(t *testing.T, err error, prototype *jwtAuthenticator, configured *jwtAuthenticator) {
				t.Helper()

				// THEN
				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, "using empty target config and step ID configured", prototype.ID())
				assert.Equal(t, "foo", configured.ID())
				assert.Equal(t, prototype.a, configured.a)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.app, configured.app)
				assert.Equal(t, prototype.trustStore, configured.trustStore)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, fmt.Sprintf("%v", prototype.r), fmt.Sprintf("%v", configured.r))
				assert.Equal(t, prototype.sf, configured.sf)
				assert.Equal(t, prototype.validateJWKCert, configured.validateJWKCert)
			},
		},
		"using unsupported fields": {
			prototypeConfig: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  issuers:
    - foobar
cache_ttl: 5s`),
			config: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, _ *jwtAuthenticator, _ *jwtAuthenticator) {
				t.Helper()

				// THEN
				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"prototype config without cache, target config with overwrites, but without cache": {
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

				assert.Equal(t, fmt.Sprintf("%v", prototype.r), fmt.Sprintf("%v", configured.r))
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.a, configured.a)

				require.NoError(t, configured.a.ScopesMatcher.Match([]string{}))
				assert.Empty(t, configured.a.Audiences)
				assert.ElementsMatch(t, configured.a.TrustedIssuers, []string{"barfoo"})
				assert.ElementsMatch(t, configured.a.AllowedAlgorithms, []string{string(jose.ES512)})

				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, prototype.validateJWKCert, configured.validateJWKCert)
				assert.Equal(t, prototype.trustStore, configured.trustStore)

				assert.Equal(t, "prototype config without cache, target config with overwrites, but without cache", configured.ID())
			},
		},
		"prototype config without cache, config with overwrites incl cache": {
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
			assert: func(t *testing.T, err error, prototype *jwtAuthenticator, configured *jwtAuthenticator) {
				t.Helper()

				// THEN
				require.NoError(t, err)

				assert.Equal(t, prototype.r, configured.r)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.a, configured.a)

				require.NoError(t, configured.a.ScopesMatcher.Match([]string{}))
				assert.Empty(t, configured.a.Audiences)
				assert.ElementsMatch(t, configured.a.TrustedIssuers, []string{"barfoo"})
				assert.ElementsMatch(t, configured.a.AllowedAlgorithms, []string{string(jose.ES512)})

				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, 5*time.Second, *configured.ttl)
				assert.Equal(t, prototype.validateJWKCert, configured.validateJWKCert)
				assert.Equal(t, prototype.trustStore, configured.trustStore)

				assert.Equal(t, "prototype config without cache, config with overwrites incl cache", configured.ID())
			},
		},
		"prototype config with cache, config without": {
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

				assert.Equal(t, fmt.Sprintf("%v", prototype.r), fmt.Sprintf("%v", configured.r))
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.a, configured.a)

				require.NoError(t, configured.a.ScopesMatcher.Match([]string{}))
				assert.Empty(t, configured.a.Audiences)
				assert.ElementsMatch(t, configured.a.TrustedIssuers, []string{"barfoo"})
				assert.ElementsMatch(t, configured.a.AllowedAlgorithms, []string{string(jose.ES512)})

				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, 5*time.Second, *configured.ttl)
				assert.Equal(t, prototype.validateJWKCert, configured.validateJWKCert)
				assert.Equal(t, prototype.trustStore, configured.trustStore)

				assert.Equal(t, "prototype config with cache, config without", configured.ID())
			},
		},
		"prototype config with cache, target config with cache only": {
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

				assert.Equal(t, fmt.Sprintf("%v", prototype.r), fmt.Sprintf("%v", configured.r))
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.Equal(t, prototype.a, configured.a)

				assert.Equal(t, 5*time.Second, *prototype.ttl)
				assert.Equal(t, 15*time.Second, *configured.ttl)
				assert.Equal(t, prototype.validateJWKCert, configured.validateJWKCert)
				assert.Equal(t, prototype.trustStore, configured.trustStore)

				assert.Equal(t, "prototype config with cache, target config with cache only", configured.ID())
			},
		},
		"prototype without scopes configured, created authenticator configures them and merges other fields": {
			prototypeConfig: []byte(`
metadata_endpoint:
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
				assert.Equal(t, prototype.r, configured.r)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.a, configured.a)
				assert.Equal(t, prototype.ttl, configured.ttl)

				assert.Equal(t, prototype.a.TrustedIssuers, configured.a.TrustedIssuers)
				assert.Equal(t, prototype.a.Audiences, configured.a.Audiences)
				assert.Equal(t, prototype.a.AllowedAlgorithms, configured.a.AllowedAlgorithms)
				assert.Equal(t, prototype.a.ValidityLeeway, configured.a.ValidityLeeway)
				assert.NotEqual(t, prototype.a.ScopesMatcher, configured.a.ScopesMatcher)
				assert.Len(t, configured.a.ScopesMatcher, 2)
				assert.Contains(t, configured.a.ScopesMatcher, "foo")
				assert.Contains(t, configured.a.ScopesMatcher, "bar")
				assert.Equal(t, prototype.validateJWKCert, configured.validateJWKCert)
				assert.Equal(t, prototype.trustStore, configured.trustStore)

				assert.Equal(t, "prototype without scopes configured, created authenticator configures them and merges other fields", configured.ID())
			},
		},
		"prototype with defaults, configured does not allow jwk trust store override": {
			prototypeConfig: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  issuers:
    - foobar
`),
			config: []byte(`trust_store: ` + trustStorePath),
			assert: func(t *testing.T, err error, _ *jwtAuthenticator, _ *jwtAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "has invalid keys: trust_store")
			},
		},
		"prototype with defaults, configured does not allow jwk validation override": {
			prototypeConfig: []byte(`
metadata_endpoint:
  url: http://test.com
`),
			config: []byte(`validate_jwk: false`),
			assert: func(t *testing.T, err error, _ *jwtAuthenticator, _ *jwtAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "has invalid keys: validate_jwk")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			validator, err := validation.NewValidator(
				validation.WithTagValidator(config.EnforcementSettings{}),
			)
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			prototype, err := newJwtAuthenticator(appCtx, uc, pc)
			require.NoError(t, err)

			// WHEN
			auth, err := prototype.WithConfig(tc.stepID, conf)

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

func TestJwtAuthenticatorExecute(t *testing.T) {
	t.Parallel()

	type HandlerIdentifier interface {
		ID() string
	}

	var (
		jwksEndpointCalled      bool
		checkJWKSRequest        func(req *http.Request)
		jwksResponseContentType string
		jwksResponseContent     []byte
		jwksResponseCode        int

		metadataEndpointCalled      bool
		checkMetadataRequest        func(req *http.Request)
		metadataResponseContentType string
		metadataResponseContent     []byte
		metadataResponseCode        int
	)

	tenSecondsTTL := 10 * time.Second
	disabledTTL := 0 * time.Second

	ks := createKS(t)
	keyOnlyEntry, err := ks.GetKey(kidKeyWithoutCert)
	require.NoError(t, err)
	keyAndCertEntry, err := ks.GetKey(kidKeyWithCert)
	require.NoError(t, err)
	keyRSAEntry, err := ks.GetKey(kidRSAKey)
	require.NoError(t, err)

	jwksWithDuplicateEntries, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		keyOnlyEntry.JWK(), keyOnlyEntry.JWK(),
	}})
	require.NoError(t, err)

	jwksWithOneKeyOnlyEntry, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		keyOnlyEntry.JWK(),
	}})
	require.NoError(t, err)

	jwksWithOneEntryWithKeyOnlyAndOneWithCertificate, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		keyOnlyEntry.JWK(), keyAndCertEntry.JWK(),
	}})
	require.NoError(t, err)

	jwksWithRSAKey, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		keyRSAEntry.JWK(),
	}})
	require.NoError(t, err)

	subjectID := "foo"
	issuer := "foobar"
	audience := "bar"

	jwtSignedWithKeyOnlyJWK := createJWT(t, keyOnlyEntry, subjectID, issuer, audience, true)

	jwtSignedWithKeyAndCertJWK := createJWT(t, keyAndCertEntry, subjectID, issuer, audience, true)
	jwtWithoutKIDSignedWithKeyAndCertJWK := createJWT(t, keyAndCertEntry, subjectID, issuer, audience, false)

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwksEndpointCalled = true

		checkJWKSRequest(r)

		if jwksResponseContent != nil {
			w.Header().Set("Content-Type", jwksResponseContentType)
			_, err := w.Write(jwksResponseContent)
			assert.NoError(t, err)
		} else {
			w.WriteHeader(jwksResponseCode)
		}
	}))

	oidcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadataEndpointCalled = true

		checkMetadataRequest(r)

		if metadataResponseContent != nil {
			w.Header().Set("Content-Type", metadataResponseContentType)
			_, err = w.Write(metadataResponseContent)
			assert.NoError(t, err)
		} else {
			w.WriteHeader(metadataResponseCode)
		}
	}))

	defer jwksSrv.Close()
	defer oidcSrv.Close()

	for uc, tc := range map[string]struct {
		authenticator  *jwtAuthenticator
		instructServer func(t *testing.T)
		configureMocks func(t *testing.T,
			ctx *heimdallmocks.RequestContextMock,
			cch *mocks.CacheMock,
			ads *mocks2.AuthDataExtractStrategyMock,
			auth *jwtAuthenticator)
		assert func(t *testing.T, err error, sub *subject.Subject)
	}{
		"with failing auth data source": {
			authenticator: &jwtAuthenticator{id: "auth3"},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("", heimdall.ErrCommunicationTimeout)
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.False(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.NotErrorIs(t, err, heimdall.ErrArgument)
				require.ErrorContains(t, err, "no JWT")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"with unsupported JWT format": {
			authenticator: &jwtAuthenticator{id: "auth3"},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("foo.bar.baz.bam", nil)
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.False(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.ErrorIs(t, err, heimdall.ErrArgument)
				require.ErrorContains(t, err, "JWS format must have three parts")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"with JWT parsing error": {
			authenticator: &jwtAuthenticator{id: "auth3"},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("foo.bar.baz", nil)
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.False(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.ErrorIs(t, err, heimdall.ErrArgument)
				require.ErrorContains(t, err, "parse JWT")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"with jwks endpoint rendering error": {
			authenticator: &jwtAuthenticator{
				id: "auth3",
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{JWKSEndpoint: &endpoint.Endpoint{URL: jwksSrv.URL + "{{ Foo }}"}}, nil
				}),
				ttl: &disabledTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.False(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "render URL")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"with jwks endpoint communication error (dns)": {
			authenticator: &jwtAuthenticator{
				id: "auth3",
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{JWKSEndpoint: &endpoint.Endpoint{URL: "http://jwks.heimdall.test.local"}}, nil
				}),
				ttl: &disabledTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.False(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrCommunication)
				require.NotErrorIs(t, err, heimdall.ErrArgument)
				require.ErrorContains(t, err, "JWKS endpoint failed")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"with unexpected response code from jwks endpoint": {
			authenticator: &jwtAuthenticator{
				id: "auth3",
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{JWKSEndpoint: &endpoint.Endpoint{URL: jwksSrv.URL}}, nil
				}),
				ttl: &disabledTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				jwksResponseCode = http.StatusInternalServerError
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.True(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrCommunication)
				require.NotErrorIs(t, err, heimdall.ErrArgument)
				require.ErrorContains(t, err, "unexpected response")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"with jwks unmarshalling error": {
			authenticator: &jwtAuthenticator{
				id: "auth3",
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						JWKSEndpoint: &endpoint.Endpoint{
							URL:     jwksSrv.URL,
							Headers: map[string]string{"Accept": "application/json"},
						},
					}, nil
				}),
				ttl: &disabledTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkJWKSRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				jwksResponseCode = http.StatusOK
				jwksResponseContent = []byte(`Hello Foo`)
				jwksResponseContentType = "text/text"
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.True(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.NotErrorIs(t, err, heimdall.ErrArgument)
				require.ErrorContains(t, err, "failed to unmarshal")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"without unique key id": {
			authenticator: &jwtAuthenticator{
				id: "auth3",
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						JWKSEndpoint: &endpoint.Endpoint{
							URL:     jwksSrv.URL,
							Headers: map[string]string{"Accept": "application/json"},
						},
					}, nil
				}),
				ttl: &disabledTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkJWKSRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				jwksResponseCode = http.StatusOK
				jwksResponseContent = jwksWithDuplicateEntries
				jwksResponseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.True(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.NotErrorIs(t, err, heimdall.ErrArgument)
				require.ErrorContains(t, err, "no (unique) key found")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"with error while communicating to the metadata endpoint": {
			authenticator: &jwtAuthenticator{
				id:  "auth3",
				r:   &oauth2.MetadataEndpoint{Endpoint: endpoint.Endpoint{URL: oidcSrv.URL}},
				ttl: &disabledTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkMetadataRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				metadataResponseCode = http.StatusBadRequest
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.False(t, jwksEndpointCalled)
				assert.True(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed retrieving oauth2 server metadata")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"with no entry for jwks_uri from the metadata endpoint": {
			authenticator: &jwtAuthenticator{
				id:  "auth3",
				r:   &oauth2.MetadataEndpoint{Endpoint: endpoint.Endpoint{URL: oidcSrv.URL}},
				ttl: &disabledTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
				// http cache
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, mock.MatchedBy(
					func(ttl time.Duration) bool { return ttl.Round(time.Minute) == 30*time.Minute },
				)).Return(nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkMetadataRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				metadataResponseContent, err = json.Marshal(map[string]string{"issuer": oidcSrv.URL})
				require.NoError(t, err)
				metadataResponseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.False(t, jwksEndpointCalled)
				assert.True(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "required jwks_uri")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"with positive cache hit, but unsupported algorithm": {
			authenticator: &jwtAuthenticator{
				id: "auth3",
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						JWKSEndpoint: &endpoint.Endpoint{
							URL:     jwksSrv.URL,
							Headers: map[string]string{"Accept": "application/json"},
						},
					}, nil
				}),
				a:   oauth2.Expectation{AllowedAlgorithms: []string{"foo"}},
				ttl: &tenSecondsTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				ep := &endpoint.Endpoint{
					URL:     jwksSrv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				}
				cacheKey := auth.calculateCacheKey(ep, jwksSrv.URL, kidKeyWithoutCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				rawKey, err := json.Marshal(&keys[0])
				require.NoError(t, err)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
				cch.EXPECT().Get(mock.Anything, cacheKey).Return(rawKey, nil)
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.False(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.NotErrorIs(t, err, heimdall.ErrArgument)
				require.ErrorContains(t, err, "algorithm is not allowed")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"with positive cache hit, but signature verification error": {
			authenticator: &jwtAuthenticator{
				id: "auth3",
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						JWKSEndpoint: &endpoint.Endpoint{
							URL:     jwksSrv.URL,
							Headers: map[string]string{"Accept": "application/json"},
						},
					}, nil
				}),
				a:   oauth2.Expectation{AllowedAlgorithms: []string{"ES384"}},
				ttl: &tenSecondsTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				ep := &endpoint.Endpoint{
					URL:     jwksSrv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				}
				cacheKey := auth.calculateCacheKey(ep, jwksSrv.URL, kidKeyWithCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				rawKey, err := json.Marshal(keys[0])
				require.NoError(t, err)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyAndCertJWK, nil)
				cch.EXPECT().Get(mock.Anything, cacheKey).Return(rawKey, nil)
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.False(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.NotErrorIs(t, err, heimdall.ErrArgument)
				require.ErrorContains(t, err, "JWT signature")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"with positive cache hit, but claims verification error": {
			authenticator: &jwtAuthenticator{
				id: "auth3",
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						JWKSEndpoint: &endpoint.Endpoint{
							URL:     jwksSrv.URL,
							Headers: map[string]string{"Accept": "application/json"},
						},
					}, nil
				}),
				a:   oauth2.Expectation{AllowedAlgorithms: []string{"ES384"}, TrustedIssuers: []string{"untrusted"}},
				ttl: &tenSecondsTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				ep := &endpoint.Endpoint{
					URL:     jwksSrv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				}
				cacheKey := auth.calculateCacheKey(ep, jwksSrv.URL, kidKeyWithoutCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				rawKey, err := json.Marshal(keys[0])
				require.NoError(t, err)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
				cch.EXPECT().Get(mock.Anything, cacheKey).Return(rawKey, nil)
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.False(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.NotErrorIs(t, err, heimdall.ErrArgument)
				require.ErrorContains(t, err, "assertion conditions")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"with positive cache hit, but subject creation error": {
			authenticator: &jwtAuthenticator{
				id: "auth3",
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						JWKSEndpoint: &endpoint.Endpoint{
							URL:     jwksSrv.URL,
							Headers: map[string]string{"Accept": "application/json"},
						},
					}, nil
				}),
				a: oauth2.Expectation{
					AllowedAlgorithms: []string{"ES384"},
					TrustedIssuers:    []string{issuer},
					ScopesMatcher:     oauth2.ExactScopeStrategyMatcher{},
				},
				sf:  &SubjectInfo{IDFrom: "foobar"},
				ttl: &tenSecondsTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				ep := &endpoint.Endpoint{
					URL:     jwksSrv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				}
				cacheKey := auth.calculateCacheKey(ep, jwksSrv.URL, kidKeyWithoutCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				rawKey, err := json.Marshal(keys[0])
				require.NoError(t, err)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
				cch.EXPECT().Get(mock.Anything, cacheKey).Return(rawKey, nil)
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.False(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.NotErrorIs(t, err, heimdall.ErrArgument)
				require.ErrorContains(t, err, "failed to extract subject")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"successful with positive cache hit": {
			authenticator: &jwtAuthenticator{
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						JWKSEndpoint: &endpoint.Endpoint{
							URL:     jwksSrv.URL,
							Headers: map[string]string{"Accept": "application/json"},
						},
					}, nil
				}),
				a: oauth2.Expectation{
					AllowedAlgorithms: []string{"ES384"},
					TrustedIssuers:    []string{issuer},
					ScopesMatcher:     oauth2.ExactScopeStrategyMatcher{},
				},
				sf:  &SubjectInfo{IDFrom: "sub"},
				ttl: &tenSecondsTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				ep := &endpoint.Endpoint{
					URL:     jwksSrv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				}
				cacheKey := auth.calculateCacheKey(ep, jwksSrv.URL, kidKeyWithoutCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				rawKey, err := json.Marshal(&keys[0])
				require.NoError(t, err)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
				cch.EXPECT().Get(mock.Anything, cacheKey).Return(rawKey, nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

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
		"successful without cache hit using key only": {
			authenticator: &jwtAuthenticator{
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						JWKSEndpoint: &endpoint.Endpoint{
							URL:     jwksSrv.URL + "/{{ .TokenIssuer }}",
							Headers: map[string]string{"Accept": "application/json"},
						},
					}, nil
				}),
				a: oauth2.Expectation{
					AllowedAlgorithms: []string{"ES384"},
					TrustedIssuers:    []string{issuer},
					ScopesMatcher:     oauth2.ExactScopeStrategyMatcher{},
				},
				sf:  &SubjectInfo{IDFrom: "sub"},
				ttl: &tenSecondsTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				ep := &endpoint.Endpoint{
					URL:     jwksSrv.URL + "/{{ .TokenIssuer }}",
					Headers: map[string]string{"Accept": "application/json"},
				}
				cacheKey := auth.calculateCacheKey(ep, fmt.Sprintf("%s/%s", jwksSrv.URL, issuer), kidKeyWithoutCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				rawKey, err := json.Marshal(keys[0])
				require.NoError(t, err)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
				cch.EXPECT().Get(mock.Anything, cacheKey).Return(nil, errors.New("no cache entry"))
				cch.EXPECT().Set(mock.Anything, cacheKey, rawKey, *auth.ttl).Return(nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkJWKSRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, "/"+issuer, req.URL.Path)
				}

				jwksResponseCode = http.StatusOK
				jwksResponseContent = jwksWithOneKeyOnlyEntry
				jwksResponseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

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
		"successful without cache hit using key & cert with disabled jwk validation": {
			authenticator: &jwtAuthenticator{
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						JWKSEndpoint: &endpoint.Endpoint{
							URL:     jwksSrv.URL,
							Headers: map[string]string{"Accept": "application/json"},
						},
					}, nil
				}),
				a: oauth2.Expectation{
					AllowedAlgorithms: []string{"ES384"},
					TrustedIssuers:    []string{issuer},
					ScopesMatcher:     oauth2.ExactScopeStrategyMatcher{},
				},
				sf:  &SubjectInfo{IDFrom: "sub"},
				ttl: &tenSecondsTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				ep := &endpoint.Endpoint{
					URL:     jwksSrv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				}
				cacheKey := auth.calculateCacheKey(ep, jwksSrv.URL, kidKeyWithCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneEntryWithKeyOnlyAndOneWithCertificate, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithCert)

				rawKey, err := json.Marshal(keys[0])
				require.NoError(t, err)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyAndCertJWK, nil)
				cch.EXPECT().Get(mock.Anything, cacheKey).Return(nil, errors.New("no cache entry"))
				cch.EXPECT().Set(mock.Anything, cacheKey, rawKey, *auth.ttl).Return(nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkJWKSRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				jwksResponseCode = http.StatusOK
				jwksResponseContent = jwksWithOneEntryWithKeyOnlyAndOneWithCertificate
				jwksResponseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

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
		"successful without cache hit using key & cert with disabled jwk validation using metadata discovery": {
			authenticator: &jwtAuthenticator{
				r: &oauth2.MetadataEndpoint{
					Endpoint:                            endpoint.Endpoint{URL: oidcSrv.URL + "/{{ .TokenIssuer }}"},
					DisableIssuerIdentifierVerification: true,
				},
				a: oauth2.Expectation{
					AllowedAlgorithms: []string{"ES384"},
					ScopesMatcher:     oauth2.ExactScopeStrategyMatcher{},
				},
				sf:  &SubjectInfo{IDFrom: "sub"},
				ttl: &tenSecondsTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				ep := &endpoint.Endpoint{
					URL:     jwksSrv.URL,
					Headers: map[string]string{"Accept": "application/json"},
					Method:  http.MethodGet,
				}
				cacheKey := auth.calculateCacheKey(ep, jwksSrv.URL, kidKeyWithCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneEntryWithKeyOnlyAndOneWithCertificate, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithCert)

				rawKey, err := json.Marshal(keys[0])
				require.NoError(t, err)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyAndCertJWK, nil)
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
				cch.EXPECT().Set(mock.Anything, cacheKey, rawKey, *auth.ttl).Return(nil)
				// http cache
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, mock.MatchedBy(
					func(ttl time.Duration) bool { return ttl.Round(time.Minute) == 30*time.Minute },
				)).Return(nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkJWKSRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}
				checkMetadataRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, "/"+issuer, req.URL.Path)
				}

				jwksResponseCode = http.StatusOK
				jwksResponseContent = jwksWithOneEntryWithKeyOnlyAndOneWithCertificate
				jwksResponseContentType = "application/json"

				metadataResponseCode = http.StatusOK
				metadataResponseContent, err = json.Marshal(map[string]string{
					"jwks_uri": jwksSrv.URL,
					"issuer":   issuer,
				})
				require.NoError(t, err)
				metadataResponseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, jwksEndpointCalled)
				assert.True(t, metadataEndpointCalled)

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
		"successful without cache hit using key & cert with enabled jwk validation using system trust store": {
			authenticator: &jwtAuthenticator{
				id: "auth3",
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						JWKSEndpoint: &endpoint.Endpoint{
							URL:     jwksSrv.URL,
							Headers: map[string]string{"Accept": "application/json"},
						},
					}, nil
				}),
				a: oauth2.Expectation{
					AllowedAlgorithms: []string{"ES384"},
					TrustedIssuers:    []string{issuer},
					ScopesMatcher:     oauth2.ExactScopeStrategyMatcher{},
				},
				sf:              &SubjectInfo{IDFrom: "sub"},
				ttl:             &tenSecondsTTL,
				validateJWKCert: true,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				ep := &endpoint.Endpoint{
					URL:     jwksSrv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				}
				cacheKey := auth.calculateCacheKey(ep, jwksSrv.URL, kidKeyWithCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneEntryWithKeyOnlyAndOneWithCertificate, &jwks)
				require.NoError(t, err)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyAndCertJWK, nil)
				cch.EXPECT().Get(mock.Anything, cacheKey).Return(nil, errors.New("no cache entry"))
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkJWKSRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				jwksResponseCode = http.StatusOK
				jwksResponseContent = jwksWithOneEntryWithKeyOnlyAndOneWithCertificate
				jwksResponseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.True(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.ErrorContains(t, err, "JWK")
				require.ErrorContains(t, err, "invalid")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"successful without cache hit using key & cert with jwk validation using custom trust store": {
			authenticator: &jwtAuthenticator{
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						JWKSEndpoint: &endpoint.Endpoint{
							URL:     jwksSrv.URL,
							Headers: map[string]string{"Accept": "application/json"},
						},
					}, nil
				}),
				a: oauth2.Expectation{
					AllowedAlgorithms: []string{"ES384"},
					TrustedIssuers:    []string{issuer},
					ScopesMatcher:     oauth2.ExactScopeStrategyMatcher{},
				},
				sf:              &SubjectInfo{IDFrom: "sub"},
				ttl:             &tenSecondsTTL,
				validateJWKCert: true,
				trustStore:      truststore.TrustStore{keyAndCertEntry.CertChain[2]},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				ep := &endpoint.Endpoint{
					URL:     jwksSrv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				}
				cacheKey := auth.calculateCacheKey(ep, jwksSrv.URL, kidKeyWithCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneEntryWithKeyOnlyAndOneWithCertificate, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithCert)

				rawKey, err := json.Marshal(keys[0])
				require.NoError(t, err)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyAndCertJWK, nil)
				cch.EXPECT().Get(mock.Anything, cacheKey).Return(nil, errors.New("no cache entry"))
				cch.EXPECT().Set(mock.Anything, cacheKey, rawKey, *auth.ttl).Return(nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkJWKSRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				jwksResponseCode = http.StatusOK
				jwksResponseContent = jwksWithOneEntryWithKeyOnlyAndOneWithCertificate
				jwksResponseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

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
		"successful validation of token without kid": {
			authenticator: &jwtAuthenticator{
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						JWKSEndpoint: &endpoint.Endpoint{
							URL:     jwksSrv.URL,
							Headers: map[string]string{"Accept": "application/json"},
						},
					}, nil
				}),
				a: oauth2.Expectation{
					AllowedAlgorithms: []string{"ES384"},
					TrustedIssuers:    []string{issuer},
					ScopesMatcher:     oauth2.ExactScopeStrategyMatcher{},
				},
				sf:              &SubjectInfo{IDFrom: "sub"},
				validateJWKCert: true,
				trustStore:      truststore.TrustStore{keyAndCertEntry.CertChain[2]},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtWithoutKIDSignedWithKeyAndCertJWK, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkJWKSRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				jwksResponseCode = http.StatusOK
				jwksResponseContent = jwksWithOneEntryWithKeyOnlyAndOneWithCertificate
				jwksResponseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

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
		"validation of token without kid fails because of jwks response unmarshalling error": {
			authenticator: &jwtAuthenticator{
				id: "auth3",
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						JWKSEndpoint: &endpoint.Endpoint{
							URL:     jwksSrv.URL,
							Headers: map[string]string{"Accept": "application/json"},
						},
					}, nil
				}),
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtWithoutKIDSignedWithKeyAndCertJWK, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkJWKSRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				jwksResponseCode = http.StatusOK
				jwksResponseContent = []byte(`Hello Foo`)
				jwksResponseContentType = "text/text"
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.True(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed to unmarshal")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"validation of token without kid fails as available keys don't have matching algorithms": {
			authenticator: &jwtAuthenticator{
				id: "auth3",
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						JWKSEndpoint: &endpoint.Endpoint{
							URL:     jwksSrv.URL,
							Headers: map[string]string{"Accept": "application/json"},
						},
					}, nil
				}),
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtWithoutKIDSignedWithKeyAndCertJWK, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkJWKSRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				jwksResponseCode = http.StatusOK
				jwksResponseContent = jwksWithRSAKey
				jwksResponseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.True(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.ErrorContains(t, err, "None of the keys")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"validation of token without kid fails as available keys could not be verified": {
			authenticator: &jwtAuthenticator{
				id: "auth3",
				r: oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{
						JWKSEndpoint: &endpoint.Endpoint{
							URL:     jwksSrv.URL,
							Headers: map[string]string{"Accept": "application/json"},
						},
					}, nil
				}),
				validateJWKCert: true,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtWithoutKIDSignedWithKeyAndCertJWK, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkJWKSRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				jwksResponseCode = http.StatusOK
				jwksResponseContent = jwksWithOneEntryWithKeyOnlyAndOneWithCertificate
				jwksResponseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.True(t, jwksEndpointCalled)
				assert.False(t, metadataEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.ErrorContains(t, err, "None of the keys")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"custom provided assertions take precedence over those coming from the metadata": {
			authenticator: &jwtAuthenticator{
				r: &oauth2.MetadataEndpoint{
					Endpoint:                            endpoint.Endpoint{URL: oidcSrv.URL},
					DisableIssuerIdentifierVerification: true,
				},
				a: oauth2.Expectation{
					ScopesMatcher:     oauth2.ExactScopeStrategyMatcher{},
					AllowedAlgorithms: []string{"ES384"},
					TrustedIssuers:    []string{"barfoo"},
				},
				sf:  &SubjectInfo{IDFrom: "sub"},
				ttl: &disabledTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyAndCertJWK, nil)
				// http cache
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, mock.MatchedBy(
					func(ttl time.Duration) bool { return ttl.Round(time.Minute) == 30*time.Minute },
				)).Return(nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkJWKSRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}
				checkMetadataRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, "/", req.URL.Path)
				}

				jwksResponseCode = http.StatusOK
				jwksResponseContent = jwksWithOneEntryWithKeyOnlyAndOneWithCertificate
				jwksResponseContentType = "application/json"

				metadataResponseCode = http.StatusOK
				metadataResponseContent, err = json.Marshal(map[string]string{
					"jwks_uri": jwksSrv.URL,
					"issuer":   issuer,
				})
				require.NoError(t, err)
				metadataResponseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.True(t, metadataEndpointCalled)
				assert.True(t, jwksEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.ErrorContains(t, err, "issuer foobar is not trusted")
			},
		},
		"resolved jwks endpoint expects authentication": {
			authenticator: &jwtAuthenticator{
				r: &oauth2.MetadataEndpoint{
					Endpoint: endpoint.Endpoint{URL: oidcSrv.URL},
					ResolvedEndpoints: map[string]oauth2.ResolvedEndpointSettings{
						"jwks_uri": {
							AuthStrategy: &authstrategy.APIKey{
								In:    "header",
								Name:  "X-Api-Key",
								Value: "very-secret",
							},
						},
					},
					DisableIssuerIdentifierVerification: true,
				},
				a: oauth2.Expectation{
					ScopesMatcher:     oauth2.ExactScopeStrategyMatcher{},
					AllowedAlgorithms: []string{"ES384"},
				},
				sf:  &SubjectInfo{IDFrom: "sub"},
				ttl: &disabledTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyAndCertJWK, nil)
				// http cache
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, mock.MatchedBy(
					func(ttl time.Duration) bool { return ttl.Round(time.Minute) == 30*time.Minute },
				)).Return(nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkJWKSRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, "very-secret", req.Header.Get("X-Api-Key"))
				}
				checkMetadataRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, "/", req.URL.Path)
				}

				jwksResponseCode = http.StatusOK
				jwksResponseContent = jwksWithOneEntryWithKeyOnlyAndOneWithCertificate
				jwksResponseContentType = "application/json"

				metadataResponseCode = http.StatusOK
				metadataResponseContent, err = json.Marshal(map[string]string{
					"jwks_uri": jwksSrv.URL,
					"issuer":   issuer,
				})
				require.NoError(t, err)
				metadataResponseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, metadataEndpointCalled)
				assert.True(t, jwksEndpointCalled)

				require.NoError(t, err)
				require.NotNil(t, sub)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			jwksEndpointCalled = false
			jwksResponseContentType = ""
			jwksResponseContent = nil
			jwksResponseCode = 0

			metadataEndpointCalled = false
			metadataResponseContentType = ""
			metadataResponseContent = nil
			metadataResponseCode = 0

			checkJWKSRequest = func(*http.Request) { t.Helper() }
			checkMetadataRequest = func(*http.Request) { t.Helper() }

			instructServer := x.IfThenElse(tc.instructServer != nil,
				tc.instructServer,
				func(t *testing.T) { t.Helper() })

			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T,
					_ *heimdallmocks.RequestContextMock,
					_ *mocks.CacheMock,
					_ *mocks2.AuthDataExtractStrategyMock,
					_ *jwtAuthenticator,
				) {
					t.Helper()
				})

			ads := mocks2.NewAuthDataExtractStrategyMock(t)
			tc.authenticator.ads = ads

			cch := mocks.NewCacheMock(t)

			ctx := heimdallmocks.NewRequestContextMock(t)
			ctx.EXPECT().Context().Return(cache.WithContext(t.Context(), cch))

			configureMocks(t, ctx, cch, ads, tc.authenticator)
			instructServer(t)

			// WHEN
			sub, err := tc.authenticator.Execute(ctx)

			// THEN
			tc.assert(t, err, sub)
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

	ee3PrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pemBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(ee1PrivKey, pemx.WithHeader("X-Key-ID", kidKeyWithCert)),
		pemx.WithECDSAPrivateKey(ee2PrivKey, pemx.WithHeader("X-Key-ID", kidKeyWithoutCert)),
		pemx.WithRSAPrivateKey(ee3PrivKey, pemx.WithHeader("X-Key-ID", kidRSAKey)),
		pemx.WithX509Certificate(ee1cert),
		pemx.WithX509Certificate(intCA1Cert),
		pemx.WithX509Certificate(rootCA1.Certificate),
	)
	require.NoError(t, err)

	ks, err := keystore.NewKeyStoreFromPEMBytes(pemBytes, "")
	require.NoError(t, err)

	return ks
}

func createJWT(t *testing.T, keyEntry *keystore.Entry, subject, issuer, audience string, setKid bool) string {
	t.Helper()

	signerOpts := &jose.SignerOptions{}
	signerOpts = signerOpts.WithType("JWT")

	if setKid {
		signerOpts = signerOpts.WithHeader("kid", keyEntry.KeyID)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: keyEntry.JOSEAlgorithm(),
			Key:       keyEntry.PrivateKey,
		},
		signerOpts)
	require.NoError(t, err)

	builder := jwt.Signed(signer)
	builder = builder.Claims(map[string]interface{}{
		"sub": subject,
		"iss": issuer,
		"jti": "foo",
		"iat": time.Now().Unix() - 1,
		"nbf": time.Now().Unix() - 1,
		// expiry should be generous in case some things take longer than expected (e.g. dns/http)
		"exp": time.Now().Unix() + 60,
		"aud": []string{audience},
		"scp": []string{"foo", "bar"},
	})

	rawJwt, err := builder.Serialize()
	require.NoError(t, err)

	return rawJwt
}

func TestJwtAuthenticatorGetCacheTTL(t *testing.T) {
	t.Parallel()

	disabledTTL := -1 * time.Second
	veryLongTTL := time.Hour * 24 * 100
	shortTTL := time.Hour * 2

	// ROOT CAs
	ca, err := testsupport.NewRootCA("Test CA", time.Hour*24)
	require.NoError(t, err)

	// EE cert 1
	ee1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	ee1cert, err := ca.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&ee1PrivKey.PublicKey, x509.ECDSAWithSHA384))
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		authenticator *jwtAuthenticator
		jwk           *jose.JSONWebKey
		assert        func(t *testing.T, ttl time.Duration)
	}{
		"jwk does not contain certificate and no ttl configured": {
			authenticator: &jwtAuthenticator{},
			jwk: &jose.JSONWebKey{
				KeyID: "1",
				Key:   ee1PrivKey.PublicKey,
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, defaultJWTAuthenticatorTTL, ttl)
			},
		},
		"jwk does not contain certificate and ttl configured": {
			authenticator: &jwtAuthenticator{ttl: &shortTTL},
			jwk: &jose.JSONWebKey{
				KeyID: "1",
				Key:   ee1PrivKey.PublicKey,
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, shortTTL, ttl)
			},
		},
		"jwk does not contain certificate and ttl disabled": {
			authenticator: &jwtAuthenticator{ttl: &disabledTTL},
			jwk: &jose.JSONWebKey{
				KeyID: "1",
				Key:   ee1PrivKey.PublicKey,
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, 0*time.Second, ttl)
			},
		},
		"jwk contains certificate and no ttl configured": {
			authenticator: &jwtAuthenticator{},
			jwk: &jose.JSONWebKey{
				KeyID:        "1",
				Key:          ee1PrivKey.PublicKey,
				Certificates: []*x509.Certificate{ee1cert},
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, defaultJWTAuthenticatorTTL, ttl)
			},
		},
		"jwk contains certificate and ttl configured to a time point exceeding the ttl of certificate": {
			authenticator: &jwtAuthenticator{ttl: &veryLongTTL},
			jwk: &jose.JSONWebKey{
				KeyID:        "1",
				Key:          ee1PrivKey.PublicKey,
				Certificates: []*x509.Certificate{ee1cert},
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				expTTL := time.Duration(ee1cert.NotAfter.Unix()-time.Now().Unix()-10) * time.Second

				assert.Equal(t, expTTL, ttl)
			},
		},
		"jwk contains certificate and ttl configured to a time point before the certificate expires": {
			authenticator: &jwtAuthenticator{ttl: &shortTTL},
			jwk: &jose.JSONWebKey{
				KeyID:        "1",
				Key:          ee1PrivKey.PublicKey,
				Certificates: []*x509.Certificate{ee1cert},
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, shortTTL, ttl)
			},
		},
		"jwk contains certificate and ttl disabled": {
			authenticator: &jwtAuthenticator{ttl: &disabledTTL},
			jwk: &jose.JSONWebKey{
				KeyID:        "1",
				Key:          ee1PrivKey.PublicKey,
				Certificates: []*x509.Certificate{ee1cert},
			},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, 0*time.Second, ttl)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			ttl := tc.authenticator.getCacheTTL(tc.jwk)

			// THEN
			tc.assert(t, ttl)
		})
	}
}

func TestJwtAuthenticatorIsInsecure(t *testing.T) {
	t.Parallel()

	// GIVEN
	auth := jwtAuthenticator{}

	// WHEN & THEN
	require.False(t, auth.IsInsecure())
}
