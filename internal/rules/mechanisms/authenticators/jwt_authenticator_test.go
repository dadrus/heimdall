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
	"net/http"
	"net/http/httptest"
	"os"
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
	"github.com/dadrus/heimdall/internal/endpoint"
	"github.com/dadrus/heimdall/internal/heimdall"
	heimdallmocks "github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
	mocks2 "github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/oauth2"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/truststore"
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

	file, err := os.CreateTemp("", "test-create-jwt-authenticator-*")
	require.NoError(t, err)

	_, err = file.Write(pemBytes)
	require.NoError(t, err)

	defer os.Remove(file.Name())

	trustStorePath := file.Name()

	for _, tc := range []struct {
		uc     string
		id     string
		config []byte
		assert func(t *testing.T, err error, a *jwtAuthenticator)
	}{
		{
			uc: "with unsupported fields",
			config: []byte(`
jwt_source:
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
jwt_source:
  - header: foo-header
assertions:
  issuers:
    - foobar
subject:
  id: some_template`),
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
subject:
  id: some_template`),
			assert: func(t *testing.T, err error, a *jwtAuthenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no trusted issuers")
			},
		},
		{
			uc: "valid configuration with defaults, without cache",
			id: "auth1",
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

				// subject settings
				sess, ok := auth.sf.(*SubjectInfo)
				require.True(t, ok)
				assert.Equal(t, "sub", sess.IDFrom)
				assert.Empty(t, sess.AttributesFrom)

				// cache settings
				assert.Nil(t, auth.ttl)

				// fallback settings
				assert.False(t, auth.IsFallbackOnErrorAllowed())

				// jwk validation settings
				assert.True(t, auth.validateJWKCert)
				assert.Empty(t, auth.trustStore)

				// handler id
				assert.Equal(t, "auth1", auth.ID())
			},
		},
		{
			uc: "valid configuration with defaults and cache",
			id: "auth1",
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

				// subject settings
				sess, ok := auth.sf.(*SubjectInfo)
				require.True(t, ok)
				assert.Equal(t, "sub", sess.IDFrom)
				assert.Empty(t, sess.AttributesFrom)

				// cache settings
				assert.NotNil(t, auth.ttl)
				assert.Equal(t, 5*time.Second, *auth.ttl)

				// fallback settings
				assert.False(t, auth.IsFallbackOnErrorAllowed())

				// jwk validation settings
				assert.True(t, auth.validateJWKCert)
				assert.Empty(t, auth.trustStore)

				// handler id
				assert.Equal(t, "auth1", auth.ID())
			},
		},
		{
			uc: "valid configuration with overwrites, without cache",
			id: "auth1",
			config: []byte(`
jwks_endpoint:
  url: http://test.com
  method: POST
  headers:
    Accept-Type: application/foobar
jwt_source:
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
subject:
  id: some_claim
allow_fallback_on_error: true
validate_jwk: false
trust_store: ` + trustStorePath),
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

				// subject settings
				sess, ok := auth.sf.(*SubjectInfo)
				require.True(t, ok)
				assert.Equal(t, "some_claim", sess.IDFrom)
				assert.Empty(t, sess.AttributesFrom)

				// cache settings
				assert.Nil(t, auth.ttl)

				// fallback settings
				assert.True(t, auth.IsFallbackOnErrorAllowed())

				// jwk validation settings
				assert.False(t, auth.validateJWKCert)
				assert.Contains(t, auth.trustStore, rootCA1.Certificate)

				// handler id
				assert.Equal(t, "auth1", auth.ID())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			a, err := newJwtAuthenticator(tc.id, conf)

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

	file, err := os.CreateTemp("", "test-create-jwt-authenticator-from-prototype-*")
	require.NoError(t, err)

	_, err = file.Write(pemBytes)
	require.NoError(t, err)

	defer os.Remove(file.Name())

	trustStorePath := file.Name()

	for _, tc := range []struct {
		uc              string
		id              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *jwtAuthenticator, configured *jwtAuthenticator)
	}{
		{
			uc: "using empty target config",
			id: "auth2",
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
				assert.Equal(t, "auth2", configured.ID())
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
			id: "auth2",
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
				assert.Equal(t, prototype.validateJWKCert, configured.validateJWKCert)
				assert.Equal(t, prototype.trustStore, configured.trustStore)

				assert.Equal(t, "auth2", configured.ID())
			},
		},
		{
			uc: "prototype config without cache, config with overwrites incl cache",
			id: "auth2",
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
				assert.Equal(t, 5*time.Second, *configured.ttl)
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.Equal(t, prototype.validateJWKCert, configured.validateJWKCert)
				assert.Equal(t, prototype.trustStore, configured.trustStore)

				assert.Equal(t, "auth2", configured.ID())
			},
		},
		{
			uc: "prototype config with cache, config without",
			id: "auth2",
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
				assert.Equal(t, 5*time.Second, *configured.ttl)
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.Equal(t, prototype.validateJWKCert, configured.validateJWKCert)
				assert.Equal(t, prototype.trustStore, configured.trustStore)

				assert.Equal(t, "auth2", configured.ID())
			},
		},
		{
			uc: "prototype config with cache, target config with cache only",
			id: "auth2",
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

				assert.Equal(t, 5*time.Second, *prototype.ttl)
				assert.Equal(t, 15*time.Second, *configured.ttl)
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.Equal(t, prototype.validateJWKCert, configured.validateJWKCert)
				assert.Equal(t, prototype.trustStore, configured.trustStore)

				assert.Equal(t, "auth2", configured.ID())
			},
		},
		{
			uc: "prototype without scopes configured, created authenticator configures them and merges other fields",
			id: "auth2",
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
				assert.Equal(t, prototype.validateJWKCert, configured.validateJWKCert)
				assert.Equal(t, prototype.trustStore, configured.trustStore)

				assert.Equal(t, "auth2", configured.ID())
			},
		},
		{
			uc: "prototype with defaults, configured allows fallback on errors",
			id: "auth2",
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
				assert.Equal(t, prototype.validateJWKCert, configured.validateJWKCert)
				assert.Equal(t, prototype.trustStore, configured.trustStore)

				assert.Equal(t, "auth2", configured.ID())
			},
		},
		{
			uc: "prototype with defaults, configured does not allow jwk trust store override",
			prototypeConfig: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  issuers:
    - foobar
cache_ttl: 5s`),
			config: []byte(`trust_store: ` + trustStorePath),
			assert: func(t *testing.T, err error, prototype *jwtAuthenticator, configured *jwtAuthenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "has invalid keys: trust_store")
			},
		},
		{
			uc: "prototype with defaults, configured does not allow jwk validation override",
			prototypeConfig: []byte(`
jwks_endpoint:
  url: http://test.com
assertions:
  issuers:
    - foobar
cache_ttl: 5s`),
			config: []byte(`validate_jwk: false`),
			assert: func(t *testing.T, err error, prototype *jwtAuthenticator, configured *jwtAuthenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "has invalid keys: validate_jwk")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newJwtAuthenticator(tc.id, pc)
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

func TestJwtAuthenticatorExecute(t *testing.T) {
	t.Parallel()

	type HandlerIdentifier interface {
		ID() string
	}

	var (
		endpointCalled bool
		checkRequest   func(req *http.Request)

		responseHeaders     map[string]string
		responseContentType string
		responseContent     []byte
		responseCode        int
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
			ctx *heimdallmocks.ContextMock,
			cch *mocks.CacheMock,
			ads *mocks2.AuthDataExtractStrategyMock,
			auth *jwtAuthenticator)
		assert func(t *testing.T, err error, sub *subject.Subject)
	}{
		{
			uc:            "with failing auth data source",
			authenticator: &jwtAuthenticator{id: "auth3"},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("", heimdall.ErrCommunicationTimeout)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.NotErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "no JWT")

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc:            "with unsupported JWT format",
			authenticator: &jwtAuthenticator{id: "auth3"},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("foo.bar.baz.bam", nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "JWS format must have three parts")

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc:            "with JWT parsing error",
			authenticator: &jwtAuthenticator{id: "auth3"},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("foo.bar.baz", nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "parse JWT")

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "with jwks endpoint communication error (dns)",
			authenticator: &jwtAuthenticator{
				id:  "auth3",
				e:   endpoint.Endpoint{URL: "http://heimdall.test.local"},
				ttl: &disabledTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.NotErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "JWKS endpoint failed")

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "with unexpected response code from server",
			authenticator: &jwtAuthenticator{
				id:  "auth3",
				e:   endpoint.Endpoint{URL: srv.URL},
				ttl: &disabledTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
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

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "with jwks unmarshalling error",
			authenticator: &jwtAuthenticator{
				id: "auth3",
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
				ttl: &disabledTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
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

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "without unique key id",
			authenticator: &jwtAuthenticator{
				id: "auth3",
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
				ttl: &disabledTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
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

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "with positive cache hit, but unsupported algorithm",
			authenticator: &jwtAuthenticator{
				id: "auth3",
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
				a:   oauth2.Expectation{AllowedAlgorithms: []string{"foo"}},
				ttl: &tenSecondsTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey(kidKeyWithoutCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
				cch.EXPECT().Get(cacheKey).Return(&keys[0])
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.NotErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "algorithm is not allowed")

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "with positive cache hit, but signature verification error",
			authenticator: &jwtAuthenticator{
				id: "auth3",
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
				a:   oauth2.Expectation{AllowedAlgorithms: []string{"ES384"}},
				ttl: &tenSecondsTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey(kidKeyWithCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyAndCertJWK, nil)
				cch.EXPECT().Get(cacheKey).Return(&keys[0])
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.NotErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "JWT signature")

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "with positive cache hit, but claims verification error",
			authenticator: &jwtAuthenticator{
				id: "auth3",
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
				a:   oauth2.Expectation{AllowedAlgorithms: []string{"ES384"}, TrustedIssuers: []string{"untrusted"}},
				ttl: &tenSecondsTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey(kidKeyWithoutCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
				cch.EXPECT().Get(cacheKey).Return(&keys[0])
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.NotErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "assertion conditions")

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "with positive cache hit, but subject creation error",
			authenticator: &jwtAuthenticator{
				id: "auth3",
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
				a: oauth2.Expectation{
					AllowedAlgorithms: []string{"ES384"},
					TrustedIssuers:    []string{issuer},
					ScopesMatcher:     oauth2.ExactScopeStrategyMatcher{},
				},
				sf:  &SubjectInfo{IDFrom: "foobar"},
				ttl: &tenSecondsTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey(kidKeyWithoutCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
				cch.EXPECT().Get(cacheKey).Return(&keys[0])
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.NotErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "failed to extract subject")

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.ID())
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
				sf:  &SubjectInfo{IDFrom: "sub"},
				ttl: &tenSecondsTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey(kidKeyWithoutCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
				cch.EXPECT().Get(cacheKey).Return(&keys[0])
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
				sf:  &SubjectInfo{IDFrom: "sub"},
				ttl: &tenSecondsTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey(kidKeyWithoutCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
				cch.EXPECT().Get(cacheKey).Return(nil)
				cch.EXPECT().Set(cacheKey, &keys[0], *auth.ttl)
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
			uc: "successful without cache hit using key & cert with disabled jwk validation",
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
				sf:  &SubjectInfo{IDFrom: "sub"},
				ttl: &tenSecondsTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey(kidKeyWithCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneEntryWithKeyOnlyAndOneWithCertificate, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithCert)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyAndCertJWK, nil)
				cch.EXPECT().Get(cacheKey).Return(nil)
				cch.EXPECT().Set(cacheKey, &keys[0], *auth.ttl)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				responseCode = http.StatusOK
				responseContent = jwksWithOneEntryWithKeyOnlyAndOneWithCertificate
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
			uc: "successful without cache hit using key & cert with enabled jwk validation using system trust store",
			authenticator: &jwtAuthenticator{
				id: "auth3",
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
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
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey(kidKeyWithCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneEntryWithKeyOnlyAndOneWithCertificate, &jwks)
				require.NoError(t, err)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyAndCertJWK, nil)
				cch.EXPECT().Get(cacheKey).Return(nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				responseCode = http.StatusOK
				responseContent = jwksWithOneEntryWithKeyOnlyAndOneWithCertificate
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "JWK")
				assert.Contains(t, err.Error(), "invalid")

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "successful without cache hit using key & cert with jwk validation using custom trust store",
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
				sf:              &SubjectInfo{IDFrom: "sub"},
				ttl:             &tenSecondsTTL,
				validateJWKCert: true,
				trustStore:      truststore.TrustStore{keyAndCertEntry.CertChain[2]},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey(kidKeyWithCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneEntryWithKeyOnlyAndOneWithCertificate, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithCert)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyAndCertJWK, nil)
				cch.EXPECT().Get(cacheKey).Return(nil)
				cch.EXPECT().Set(cacheKey, &keys[0], *auth.ttl)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				responseCode = http.StatusOK
				responseContent = jwksWithOneEntryWithKeyOnlyAndOneWithCertificate
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
				sf:  &SubjectInfo{IDFrom: "sub"},
				ttl: &tenSecondsTTL,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *jwtAuthenticator,
			) {
				t.Helper()

				cacheKey := auth.calculateCacheKey(kidKeyWithoutCert)

				var jwks jose.JSONWebKeySet
				err := json.Unmarshal(jwksWithOneKeyOnlyEntry, &jwks)
				require.NoError(t, err)

				keys := jwks.Key(kidKeyWithoutCert)

				ads.EXPECT().GetAuthData(ctx).Return(jwtSignedWithKeyOnlyJWK, nil)
				cch.EXPECT().Get(cacheKey).Return("Hi Foo")
				cch.EXPECT().Delete(cacheKey)
				cch.EXPECT().Set(cacheKey, &keys[0], *auth.ttl)
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
			uc: "successful validation of token without kid",
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
				sf:              &SubjectInfo{IDFrom: "sub"},
				validateJWKCert: true,
				trustStore:      truststore.TrustStore{keyAndCertEntry.CertChain[2]},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtWithoutKIDSignedWithKeyAndCertJWK, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				responseCode = http.StatusOK
				responseContent = jwksWithOneEntryWithKeyOnlyAndOneWithCertificate
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
			uc: "validation of token without kid fails because of jwks response unmarshalling error",
			authenticator: &jwtAuthenticator{
				id: "auth3",
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtWithoutKIDSignedWithKeyAndCertJWK, nil)
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

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "validation of token without kid fails as available keys don't have matching algorithms",
			authenticator: &jwtAuthenticator{
				id: "auth3",
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtWithoutKIDSignedWithKeyAndCertJWK, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				responseCode = http.StatusOK
				responseContent = jwksWithRSAKey
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "None of the keys")

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		{
			uc: "validation of token without kid fails as available keys could not be verified",
			authenticator: &jwtAuthenticator{
				id: "auth3",
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Accept": "application/json"},
				},
				validateJWKCert: true,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *jwtAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return(jwtWithoutKIDSignedWithKeyAndCertJWK, nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
				}

				responseCode = http.StatusOK
				responseContent = jwksWithOneEntryWithKeyOnlyAndOneWithCertificate
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "None of the keys")

				var identifier HandlerIdentifier
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "auth3", identifier.ID())
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
					_ *heimdallmocks.ContextMock,
					_ *mocks.CacheMock,
					_ *mocks2.AuthDataExtractStrategyMock,
					_ *jwtAuthenticator,
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
		"exp": time.Now().Unix() + 2,
		"aud": []string{audience},
		"scp": []string{"foo", "bar"},
	})

	rawJwt, err := builder.CompactSerialize()
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

	for _, tc := range []struct {
		uc            string
		authenticator *jwtAuthenticator
		jwk           *jose.JSONWebKey
		assert        func(t *testing.T, ttl time.Duration)
	}{
		{
			uc:            "jwk does not contain certificate and no ttl configured",
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
		{
			uc:            "jwk does not contain certificate and ttl configured",
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
		{
			uc:            "jwk does not contain certificate and ttl disabled",
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
		{
			uc:            "jwk contains certificate and no ttl configured",
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
		{
			uc:            "jwk contains certificate and ttl configured to a time point exceeding the ttl of certificate",
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
		{
			uc:            "jwk contains certificate and ttl configured to a time point before the certificate expires",
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
		{
			uc:            "jwk contains certificate and ttl disabled",
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
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			ttl := tc.authenticator.getCacheTTL(tc.jwk)

			// THEN
			tc.assert(t, ttl)
		})
	}
}
