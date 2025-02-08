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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	heimdallmocks "github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
	mocks2 "github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestGenericAuthenticatorCreate(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		enforceTLS  bool
		config      []byte
		assertError func(t *testing.T, err error, auth *genericAuthenticator)
	}{
		"config with undefined fields": {
			config: []byte(`
foo: bar
identity_info_endpoint:
  url: http://test.com
subject:
  id: some_template`),
			assertError: func(t *testing.T, err error, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		"missing url config": {
			config: []byte(`
authentication_data_source:
  - header: foo-header
subject:
  id: some_template`),
			assertError: func(t *testing.T, err error, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'identity_info_endpoint' is a required field")
			},
		},
		"bad url config": {
			config: []byte(`
identity_info_endpoint:
  url: test.com
authentication_data_source:
  - header: foo-header
subject:
  id: some_template`),
			assertError: func(t *testing.T, err error, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'identity_info_endpoint'.'url' must be a valid URL")
			},
		},
		"missing subject config": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
authentication_data_source:
  - header: foo-header`),
			assertError: func(t *testing.T, err error, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'subject' is a required field")
			},
		},
		"missing authentication data source config": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
subject:
  id: some_template`),
			assertError: func(t *testing.T, err error, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'authentication_data_source' is a required field")
			},
		},
		"missing subject id config": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
subject:
  attributes: some_template
authentication_data_source:
  - header: foo-header`),
			assertError: func(t *testing.T, err error, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'subject'.'id' is a required field")
			},
		},
		"with valid configuration but disabled cache": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: GET
authentication_data_source:
  - header: foo-header
payload: |
  { "foo": {{ quote .AuthenticationData }} }
subject:
  id: some_template`),
			assertError: func(t *testing.T, err error, auth *genericAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, auth)
				assert.Equal(t, "http://test.com", auth.e.URL)
				assert.Equal(t, http.MethodGet, auth.e.Method)
				ces, ok := auth.ads.(extractors.CompositeExtractStrategy)
				assert.True(t, ok)
				assert.Len(t, ces, 1)
				assert.Contains(t, ces, &extractors.HeaderValueExtractStrategy{Name: "foo-header"})
				assert.NotNil(t, auth.payload)
				assert.Empty(t, auth.fwdCookies)
				assert.Empty(t, auth.fwdHeaders)
				assert.Equal(t, &SubjectInfo{IDFrom: "some_template"}, auth.sf)
				assert.Equal(t, time.Duration(0), auth.ttl)
				assert.False(t, auth.IsFallbackOnErrorAllowed())
				assert.Nil(t, auth.sessionLifespanConf)
				assert.Equal(t, "auth1", auth.ID())
			},
		},
		"with valid configuration and enabled cache and TLS enforcement": {
			enforceTLS: true,
			config: []byte(`
identity_info_endpoint:
  url: https://test.com
  method: POST
authentication_data_source:
  - cookie: foo-cookie
subject:
  id: some_template
cache_ttl: 5s`),
			assertError: func(t *testing.T, err error, auth *genericAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, auth)
				assert.Equal(t, "http://test.com", auth.e.URL)
				assert.Equal(t, http.MethodPost, auth.e.Method)
				ces, ok := auth.ads.(extractors.CompositeExtractStrategy)
				assert.True(t, ok)
				assert.Len(t, ces, 1)
				assert.Contains(t, ces, &extractors.CookieValueExtractStrategy{Name: "foo-cookie"})
				assert.Nil(t, auth.payload)
				assert.Empty(t, auth.fwdCookies)
				assert.Empty(t, auth.fwdHeaders)
				assert.Equal(t, &SubjectInfo{IDFrom: "some_template"}, auth.sf)
				assert.Equal(t, 5*time.Second, auth.ttl)
				assert.False(t, auth.IsFallbackOnErrorAllowed())
				assert.Nil(t, auth.sessionLifespanConf)
				assert.Equal(t, "auth1", auth.ID())
			},
		},
		"with valid configuration enabling fallback on errors and header forwarding": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - cookie: foo-cookie
forward_cookies:
  - foo-cookie
subject:
  id: some_template
allow_fallback_on_error: true`),
			assertError: func(t *testing.T, err error, auth *genericAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, auth)
				assert.Equal(t, "http://test.com", auth.e.URL)
				assert.Equal(t, http.MethodPost, auth.e.Method)
				ces, ok := auth.ads.(extractors.CompositeExtractStrategy)
				assert.True(t, ok)
				assert.Len(t, ces, 1)
				assert.Contains(t, ces, &extractors.CookieValueExtractStrategy{Name: "foo-cookie"})
				assert.Nil(t, auth.payload)
				assert.Len(t, auth.fwdCookies, 1)
				assert.Contains(t, auth.fwdCookies, "foo-cookie")
				assert.Empty(t, auth.fwdHeaders)
				assert.Equal(t, &SubjectInfo{IDFrom: "some_template"}, auth.sf)
				assert.Equal(t, time.Duration(0), auth.ttl)
				assert.True(t, auth.IsFallbackOnErrorAllowed())
				assert.Nil(t, auth.sessionLifespanConf)
				assert.Equal(t, "auth1", auth.ID())
			},
		},
		"with session lifespan config and forward header": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: PATCH
authentication_data_source:
  - cookie: foo-cookie
forward_headers:
  - X-My-Header
subject:
  id: some_template
session_lifespan:
  active: foo
  issued_at: bar
  not_before: baz
  not_after: zab
  time_format: foo bar
  validity_leeway: 2s`),
			assertError: func(t *testing.T, err error, auth *genericAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, auth)
				assert.Equal(t, "http://test.com", auth.e.URL)
				assert.Equal(t, http.MethodPatch, auth.e.Method)
				ces, ok := auth.ads.(extractors.CompositeExtractStrategy)
				assert.True(t, ok)
				assert.Len(t, ces, 1)
				assert.Contains(t, ces, &extractors.CookieValueExtractStrategy{Name: "foo-cookie"})
				assert.Nil(t, auth.payload)
				assert.Len(t, auth.fwdHeaders, 1)
				assert.Contains(t, auth.fwdHeaders, "X-My-Header")
				assert.Empty(t, auth.fwdCookies)
				assert.Equal(t, &SubjectInfo{IDFrom: "some_template"}, auth.sf)
				assert.Equal(t, time.Duration(0), auth.ttl)
				assert.False(t, auth.IsFallbackOnErrorAllowed())
				assert.NotNil(t, auth.sessionLifespanConf)
				assert.Equal(t, "foo", auth.sessionLifespanConf.ActiveField)
				assert.Equal(t, "bar", auth.sessionLifespanConf.IssuedAtField)
				assert.Equal(t, "baz", auth.sessionLifespanConf.NotBeforeField)
				assert.Equal(t, "zab", auth.sessionLifespanConf.NotAfterField)
				assert.Equal(t, "foo bar", auth.sessionLifespanConf.TimeFormat)
				assert.Equal(t, 2*time.Second, auth.sessionLifespanConf.ValidityLeeway)
				assert.Equal(t, "auth1", auth.ID())
			},
		},
		"with disabled, but enforced TLS of identity info endpoint url": {
			enforceTLS: true,
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
authentication_data_source:
  - header: foo-header
payload: |
  { "foo": {{ quote .AuthenticationData }} }
subject:
  id: some_template`),
			assertError: func(t *testing.T, err error, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'identity_info_endpoint'.'url' scheme must be https")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			es := config.EnforcementSettings{EnforceEgressTLS: tc.enforceTLS}
			validator, err := validation.NewValidator(
				validation.WithTagValidator(es),
				validation.WithErrorTranslator(es),
			)
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			auth, err := newGenericAuthenticator(appCtx, "auth1", conf)

			// THEN
			tc.assertError(t, err, auth)
		})
	}
}

func TestGenericAuthenticatorWithConfig(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		id              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *genericAuthenticator,
			configured *genericAuthenticator)
	}{
		"prototype config without cache configured and empty target config": {
			id: "auth2",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
forward_headers:
  - X-My-Header
forward_cookies:
  - foo-cookie
payload: |
  foo=bar
subject:
  id: some_template
allow_fallback_on_error: true`),
			assert: func(t *testing.T, err error, prototype *genericAuthenticator,
				configured *genericAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
				assert.Equal(t, "auth2", configured.ID())
			},
		},
		"with unsupported fields in target config": {
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
subject:
  id: some_template`),
			config: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, _ *genericAuthenticator,
				_ *genericAuthenticator,
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		"prototype config without cache, config with cache": {
			id: "auth2",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
forward_headers:
  - X-My-Header
forward_cookies:
  - foo-cookie
payload: |
  foo=bar
subject:
  id: some_template`),
			config: []byte(`cache_ttl: 5s`),
			assert: func(t *testing.T, err error, prototype *genericAuthenticator,
				configured *genericAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.payload, configured.payload)
				assert.Equal(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Equal(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.Equal(t, time.Duration(0), prototype.ttl)
				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, 5*time.Second, configured.ttl)
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.Equal(t, prototype.sessionLifespanConf, configured.sessionLifespanConf)
				assert.Equal(t, "auth2", configured.ID())
			},
		},
		"prototype config with disabled fallback on error, config with enabled fallback on error": {
			id: "auth2",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
subject:
  id: some_template`),
			config: []byte(`allow_fallback_on_error: true`),
			assert: func(t *testing.T, err error, prototype *genericAuthenticator,
				configured *genericAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.payload, configured.payload)
				assert.Equal(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Equal(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.NotEqual(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.True(t, configured.IsFallbackOnErrorAllowed())
				assert.Equal(t, prototype.sessionLifespanConf, configured.sessionLifespanConf)
				assert.Equal(t, "auth2", configured.ID())
			},
		},
		"prototype config with cache ttl, config with cache tll": {
			id: "auth2",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
forward_headers:
  - X-My-Header
payload: |
  foo=bar
subject:
  id: some_template
cache_ttl: 5s`),
			config: []byte(`
cache_ttl: 15s`),
			assert: func(t *testing.T, err error, prototype *genericAuthenticator,
				configured *genericAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.payload, configured.payload)
				assert.Equal(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Equal(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, 15*time.Second, configured.ttl)
				assert.Equal(t, 5*time.Second, prototype.ttl)
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.Equal(t, prototype.sessionLifespanConf, configured.sessionLifespanConf)
				assert.Equal(t, "auth2", configured.ID())
			},
		},
		"prototype with session lifespan config and empty target config": {
			id: "auth2",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
forward_cookies:
  - foo-cookie
payload: |
  foo=bar
subject:
  id: some_template
cache_ttl: 5s
session_lifespan:
  active: foo
  issued_at: bar
  not_before: baz
  not_after: zab
  time_format: foo bar
  validity_leeway: 2s`),
			assert: func(t *testing.T, err error, prototype *genericAuthenticator,
				configured *genericAuthenticator,
			) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.payload, configured.payload)
				assert.Equal(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Equal(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.Equal(t, prototype.sessionLifespanConf, configured.sessionLifespanConf)
				assert.NotNil(t, configured.sessionLifespanConf)
				assert.Equal(t, "foo", configured.sessionLifespanConf.ActiveField)
				assert.Equal(t, "bar", configured.sessionLifespanConf.IssuedAtField)
				assert.Equal(t, "baz", configured.sessionLifespanConf.NotBeforeField)
				assert.Equal(t, "zab", configured.sessionLifespanConf.NotAfterField)
				assert.Equal(t, "foo bar", configured.sessionLifespanConf.TimeFormat)
				assert.Equal(t, 2*time.Second, configured.sessionLifespanConf.ValidityLeeway)
				assert.Equal(t, "auth2", configured.ID())
			},
		},
		"reconfiguration of identity_info_endpoint not possible": {
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
subject:
  id: some_template`),
			config: []byte(`
identity_info_endpoint:
  url: http://foo.bar
`),
			assert: func(t *testing.T, err error, _ *genericAuthenticator,
				_ *genericAuthenticator,
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		"reconfiguration of authentication_data_source not possible": {
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
subject:
  id: some_template`),
			config: []byte(`
authentication_data_source:
  - header: bar-header
`),
			assert: func(t *testing.T, err error, _ *genericAuthenticator,
				_ *genericAuthenticator,
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		"reconfiguration of subject not possible": {
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
subject:
  id: some_template`),
			config: []byte(`
subject:
  id: new_template
`),
			assert: func(t *testing.T, err error, _ *genericAuthenticator,
				_ *genericAuthenticator,
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		"reconfiguration of session_lifespan not possible": {
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
subject:
  id: some_template`),
			config: []byte(`
session_lifespan:
  active: foo
`),
			assert: func(t *testing.T, err error, _ *genericAuthenticator,
				_ *genericAuthenticator,
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		"reconfiguration of payload not possible": {
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
subject:
  id: some_template`),
			config: []byte(`
payload: |
  foo=bar
`),
			assert: func(t *testing.T, err error, _ *genericAuthenticator,
				_ *genericAuthenticator,
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		"reconfiguration of header to be forwarded not possible": {
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
subject:
  id: some_template`),
			config: []byte(`
forward_headers:
  - foo-bar
`),
			assert: func(t *testing.T, err error, _ *genericAuthenticator,
				_ *genericAuthenticator,
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		"reconfiguration of cookies to be forwarded not possible": {
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
subject:
  id: some_template`),
			config: []byte(`
forward_cookies:
  - foo-bar
`),
			assert: func(t *testing.T, err error, _ *genericAuthenticator,
				_ *genericAuthenticator,
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
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

			prototype, err := newGenericAuthenticator(appCtx, tc.id, pc)
			require.NoError(t, err)

			// WHEN
			auth, err := prototype.WithConfig(conf)

			// THEN
			var (
				genAuth *genericAuthenticator
				ok      bool
			)

			if err == nil {
				genAuth, ok = auth.(*genericAuthenticator)
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, genAuth)
		})
	}
}

func TestGenericAuthenticatorExecute(t *testing.T) {
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

	for uc, tc := range map[string]struct {
		authenticator  *genericAuthenticator
		instructServer func(t *testing.T)
		configureMocks func(t *testing.T,
			ctx *heimdallmocks.ContextMock,
			cch *mocks.CacheMock,
			ads *mocks2.AuthDataExtractStrategyMock,
			auth *genericAuthenticator)
		assert func(t *testing.T, err error, sub *subject.Subject)
	}{
		"with failing auth data source": {
			authenticator: &genericAuthenticator{id: "auth3"},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *genericAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("", heimdall.ErrCommunicationTimeout)
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "failed to get authentication data")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"with error while rendering payload": {
			authenticator: &genericAuthenticator{
				id: "auth3",
				e:  endpoint.Endpoint{URL: srv.URL},
				payload: func() template.Template {
					tpl, err := template.New("foo={{ len .Foobar }}")
					require.NoError(t, err)

					return tpl
				}(),
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *genericAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("test", nil)
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to render payload")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"with error while rendering query parameter": {
			authenticator: &genericAuthenticator{
				id: "auth3",
				e:  endpoint.Endpoint{URL: srv.URL + "?foo={{ urlenc foobar }}"},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *genericAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("test", nil)
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to render URL")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"with endpoint communication error (dns)": {
			authenticator: &genericAuthenticator{
				id: "auth3",
				e:  endpoint.Endpoint{URL: "http://heimdall.test.local"},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *genericAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("session_token", nil)
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "request to the endpoint")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"with unexpected response code from server": {
			authenticator: &genericAuthenticator{
				id: "auth3",
				e:  endpoint.Endpoint{URL: srv.URL},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *genericAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("session_token", nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				responseCode = http.StatusInternalServerError
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "unexpected response code")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"with error while extracting subject information": {
			authenticator: &genericAuthenticator{
				id: "auth3",
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
					Headers: map[string]string{
						"Accept":      "application/json",
						"X-User-Data": "{{ .AuthenticationData }}",
					},
				},
				sf: &SubjectInfo{IDFrom: "barfoo"},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *genericAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("session_token", nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, http.MethodGet, req.Method)
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, "session_token", req.Header.Get("X-User-Data"))
				}

				responseCode = http.StatusOK
				responseContent = []byte(`{ "user_id": "barbar" }`)
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to extract subject")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"successful execution without cache usage, forwarding auth data in payload, header & query": {
			authenticator: &genericAuthenticator{
				e: endpoint.Endpoint{
					URL:    srv.URL + "?foo={{ .AuthenticationData }}",
					Method: http.MethodGet,
					Headers: map[string]string{
						"Accept":      "application/json",
						"X-Auth-Data": "{{ .AuthenticationData }}",
					},
				},
				sf: &SubjectInfo{IDFrom: "user_id"},
				payload: func() template.Template {
					tpl, err := template.New("foo={{ .AuthenticationData }}")
					require.NoError(t, err)

					return tpl
				}(),
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				_ *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *genericAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("session_token", nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, http.MethodGet, req.Method)
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, "session_token", req.Header.Get("X-Auth-Data"))

					assert.Equal(t, "session_token", req.URL.Query().Get("foo"))

					res, err := io.ReadAll(req.Body)
					require.NoError(t, err)
					assert.Equal(t, "foo=session_token", string(res))
				}

				responseCode = http.StatusOK
				responseContent = []byte(`{ "user_id": "barbar" }`)
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "barbar", sub.ID)
				assert.Len(t, sub.Attributes, 1)
			},
		},
		"successful execution with positive cache hit": {
			authenticator: &genericAuthenticator{
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
					Headers: map[string]string{
						"Accept":      "application/json",
						"X-Auth-Data": "{{ .AuthenticationData }}",
					},
				},
				sf:  &SubjectInfo{IDFrom: "user_id"},
				ttl: 5 * time.Second,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *genericAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("session_token", nil)
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return([]byte(`{ "user_id": "barbar" }`), nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "barbar", sub.ID)
				assert.Len(t, sub.Attributes, 1)
			},
		},
		"successful execution with negative cache hit and header forwarding": {
			authenticator: &genericAuthenticator{
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
					Headers: map[string]string{
						"Accept": "application/json",
					},
				},
				sf:         &SubjectInfo{IDFrom: "user_id"},
				fwdHeaders: []string{"X-Original-Auth"},
				ttl:        5 * time.Second,
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				auth *genericAuthenticator,
			) {
				t.Helper()

				reqFuns := heimdallmocks.NewRequestFunctionsMock(t)
				reqFuns.EXPECT().Header("X-Original-Auth").Return("orig-auth")

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: reqFuns})

				ads.EXPECT().GetAuthData(ctx).Return("session_token", nil)
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("test error"))
				cch.EXPECT().Set(mock.Anything, mock.Anything, []byte(`{ "user_id": "barbar" }`), auth.ttl).Return(nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, http.MethodGet, req.Method)
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, "orig-auth", req.Header.Get("X-Original-Auth"))
				}

				responseCode = http.StatusOK
				responseContent = []byte(`{ "user_id": "barbar" }`)
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "barbar", sub.ID)
				assert.Len(t, sub.Attributes, 1)
			},
		},
		"execution with not active session and cookie forwarding": {
			authenticator: &genericAuthenticator{
				id: "auth3",
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
					Headers: map[string]string{
						"Accept": "application/json",
					},
				},
				sf:                  &SubjectInfo{IDFrom: "user_id"},
				fwdCookies:          []string{"original-auth"},
				ttl:                 5 * time.Second,
				sessionLifespanConf: &SessionLifespanConfig{ActiveField: "active"},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *genericAuthenticator,
			) {
				t.Helper()

				reqFuns := heimdallmocks.NewRequestFunctionsMock(t)
				reqFuns.EXPECT().Cookie("original-auth").Return("orig-auth")

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: reqFuns})

				ads.EXPECT().GetAuthData(ctx).Return("session_token", nil)
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, http.MethodGet, req.Method)
					assert.Equal(t, "application/json", req.Header.Get("Accept"))

					cookie, err := req.Cookie("original-auth")
					require.NoError(t, err)
					assert.Equal(t, "orig-auth", cookie.Value)
				}

				responseCode = http.StatusOK
				responseContent = []byte(`{ "user_id": "barbar", "active": false }`)
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				assert.Contains(t, err.Error(), "not active")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"execution with error while parsing session lifespan": {
			authenticator: &genericAuthenticator{
				id: "auth3",
				e: endpoint.Endpoint{
					URL:    srv.URL + "?foo={{ .AuthenticationData }}",
					Method: http.MethodGet,
					Headers: map[string]string{
						"Accept": "application/json",
					},
				},
				sf:                  &SubjectInfo{IDFrom: "user_id"},
				ttl:                 5 * time.Second,
				sessionLifespanConf: &SessionLifespanConfig{IssuedAtField: "iat"},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *genericAuthenticator,
			) {
				t.Helper()

				ads.EXPECT().GetAuthData(ctx).Return("session_token", nil)
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, http.MethodGet, req.Method)
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, "session_token", req.URL.Query().Get("foo"))
				}

				responseCode = http.StatusOK
				responseContent = []byte(`{ "user_id": "barbar", "iat": "2006-01-02T15:04:05.999999Z07" }`)
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed parsing issued_at")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"execution with session lifespan ttl limiting the configured ttl": {
			authenticator: &genericAuthenticator{
				e: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
					Headers: map[string]string{
						"Accept": "application/json",
					},
				},
				payload: func() template.Template {
					tpl, err := template.New("foo={{ .AuthenticationData }}")
					require.NoError(t, err)

					return tpl
				}(),
				sf:                  &SubjectInfo{IDFrom: "user_id"},
				ttl:                 30 * time.Second,
				sessionLifespanConf: &SessionLifespanConfig{NotAfterField: "exp"},
			},
			configureMocks: func(t *testing.T,
				ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock,
				ads *mocks2.AuthDataExtractStrategyMock,
				_ *genericAuthenticator,
			) {
				t.Helper()

				exp := strconv.FormatInt(time.Now().Add(15*time.Second).Unix(), 10)

				ads.EXPECT().GetAuthData(ctx).Return("session_token", nil)
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
				cch.EXPECT().Set(mock.Anything, mock.Anything, []byte(`{ "user_id": "barbar", "exp": `+exp+` }`), 5*time.Second).Return(nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				exp := strconv.FormatInt(time.Now().Add(15*time.Second).Unix(), 10)

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, http.MethodGet, req.Method)
					assert.Equal(t, "application/json", req.Header.Get("Accept"))

					res, err := io.ReadAll(req.Body)
					require.NoError(t, err)
					assert.Equal(t, "foo=session_token", string(res))
				}

				responseCode = http.StatusOK
				responseContent = []byte(`{ "user_id": "barbar", "exp": ` + exp + ` }`)
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "barbar", sub.ID)
				assert.Len(t, sub.Attributes, 2)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
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
					_ *genericAuthenticator,
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

func TestGenericAuthenticatorGetCacheTTL(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		authenticator   *genericAuthenticator
		sessionLifespan *SessionLifespan
		assert          func(t *testing.T, ttl time.Duration)
	}{
		"cache disabled": {
			authenticator: &genericAuthenticator{},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, time.Duration(0), ttl)
			},
		},
		"cache enabled, session lifespan not available": {
			authenticator: &genericAuthenticator{ttl: 5 * time.Minute},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, 5*time.Minute, ttl)
			},
		},
		"cache enabled, session lifespan available, but not_after is not available": {
			authenticator:   &genericAuthenticator{ttl: 5 * time.Minute},
			sessionLifespan: &SessionLifespan{},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, 5*time.Minute, ttl)
			},
		},
		"cache enabled, session lifespan available with not_after set to a future date exceeding configured ttl": {
			authenticator:   &genericAuthenticator{ttl: 5 * time.Minute},
			sessionLifespan: &SessionLifespan{exp: time.Now().Add(24 * time.Hour)},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, 5*time.Minute, ttl)
			},
		},
		"cache enabled, session lifespan available with not_after set to a date so that the configured ttl " +
			"would exceed the lifespan": {
			authenticator:   &genericAuthenticator{ttl: 5 * time.Minute},
			sessionLifespan: &SessionLifespan{exp: time.Now().Add(30 * time.Second)},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, 20*time.Second, ttl) // leeway of 10 sec considered
			},
		},
		"cache enabled, session lifespan available with not_after set to a date which disables ttl": {
			authenticator:   &genericAuthenticator{ttl: 5 * time.Minute},
			sessionLifespan: &SessionLifespan{exp: time.Now().Add(5 * time.Second)},
			assert: func(t *testing.T, ttl time.Duration) {
				t.Helper()

				assert.Equal(t, 0*time.Second, ttl)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			ttl := tc.authenticator.getCacheTTL(tc.sessionLifespan)

			// THEN
			tc.assert(t, ttl)
		})
	}
}

func TestGenericAuthenticatorIsInsecure(t *testing.T) {
	t.Parallel()

	// GIVEN
	auth := genericAuthenticator{}

	// WHEN & THEN
	require.False(t, auth.IsInsecure())
}
