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
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

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
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
	mocks2 "github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/identity"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewGenericAuthenticator(t *testing.T) {
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
principal:
  id: some_template`),
			assertError: func(t *testing.T, err error, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"missing url config": {
			config: []byte(`
authentication_data_source:
  - header: foo-header
principal:
  id: some_template`),
			assertError: func(t *testing.T, err error, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'identity_info_endpoint' is a required field")
			},
		},
		"bad url config": {
			config: []byte(`
identity_info_endpoint:
  url: test.com
authentication_data_source:
  - header: foo-header
principal:
  id: some_template`),
			assertError: func(t *testing.T, err error, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'identity_info_endpoint'.'url' must be a valid URL")
			},
		},
		"missing principal config": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
authentication_data_source:
  - header: foo-header`),
			assertError: func(t *testing.T, err error, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'principal' is a required field")
			},
		},
		"missing authentication data source config": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
principal:
  id: some_template`),
			assertError: func(t *testing.T, err error, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'authentication_data_source' is a required field")
			},
		},
		"missing principal id config": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
principal:
  attributes: some_template
authentication_data_source:
  - header: foo-header`),
			assertError: func(t *testing.T, err error, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'principal'.'id' is a required field")
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
principal:
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
				assert.Equal(t, &PrincipalInfo{IDFrom: "some_template"}, auth.sf)
				assert.Equal(t, time.Duration(0), auth.ttl)
				assert.Nil(t, auth.sessionLifespanConf)
				assert.Equal(t, auth.ID(), auth.Name())
				assert.Equal(t, "auth1", auth.ID())
				assert.Equal(t, "default", auth.principalName)
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
principal:
  id: some_template
cache_ttl: 5s`),
			assertError: func(t *testing.T, err error, auth *genericAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, auth)
				assert.Equal(t, "https://test.com", auth.e.URL)
				assert.Equal(t, http.MethodPost, auth.e.Method)
				ces, ok := auth.ads.(extractors.CompositeExtractStrategy)
				assert.True(t, ok)
				assert.Len(t, ces, 1)
				assert.Contains(t, ces, &extractors.CookieValueExtractStrategy{Name: "foo-cookie"})
				assert.Nil(t, auth.payload)
				assert.Empty(t, auth.fwdCookies)
				assert.Empty(t, auth.fwdHeaders)
				assert.Equal(t, &PrincipalInfo{IDFrom: "some_template"}, auth.sf)
				assert.Equal(t, 5*time.Second, auth.ttl)
				assert.Nil(t, auth.sessionLifespanConf)
				assert.Equal(t, auth.ID(), auth.Name())
				assert.Equal(t, "auth1", auth.ID())
				assert.Equal(t, "default", auth.principalName)
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
principal:
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
				assert.Equal(t, &PrincipalInfo{IDFrom: "some_template"}, auth.sf)
				assert.Equal(t, time.Duration(0), auth.ttl)
				assert.NotNil(t, auth.sessionLifespanConf)
				assert.Equal(t, "foo", auth.sessionLifespanConf.ActiveField)
				assert.Equal(t, "bar", auth.sessionLifespanConf.IssuedAtField)
				assert.Equal(t, "baz", auth.sessionLifespanConf.NotBeforeField)
				assert.Equal(t, "zab", auth.sessionLifespanConf.NotAfterField)
				assert.Equal(t, "foo bar", auth.sessionLifespanConf.TimeFormat)
				assert.Equal(t, 2*time.Second, auth.sessionLifespanConf.ValidityLeeway)
				assert.Equal(t, auth.ID(), auth.Name())
				assert.Equal(t, "auth1", auth.ID())
				assert.Equal(t, "default", auth.principalName)
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
principal:
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
			appCtx.EXPECT().Logger().Return(log.Logger)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			mech, err := newGenericAuthenticator(appCtx, "auth1", conf)

			// THEN
			auth, ok := mech.(*genericAuthenticator)
			if err == nil {
				require.True(t, ok)
			}

			tc.assertError(t, err, auth)
		})
	}
}

func TestGenericAuthenticatorCreateStep(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config  []byte
		stepDef types.StepDefinition
		assert  func(t *testing.T, err error, prototype, configured *genericAuthenticator)
	}{
		"prototype config without cache configured and empty target config": {
			config: []byte(`
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
principal:
  id: some_template`),
			assert: func(t *testing.T, err error, prototype, configured *genericAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		"with unsupported fields in target config": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
principal:
  id: some_template`),
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"foo": "bar"}},
			assert: func(t *testing.T, err error, prototype, configured *genericAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		"prototype config without cache, config with cache": {
			config: []byte(`
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
principal:
  id: some_template`),
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"cache_ttl": "5s"}},
			assert: func(t *testing.T, err error, prototype, configured *genericAuthenticator) {
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
				assert.Equal(t, prototype.sessionLifespanConf, configured.sessionLifespanConf)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.Equal(t, "prototype config without cache, config with cache", configured.ID())
				assert.Equal(t, prototype.principalName, configured.principalName)
			},
		},
		"prototype config with cache ttl, config with cache tll": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
forward_headers:
  - X-My-Header
payload: |
  foo=bar
principal:
  id: some_template
cache_ttl: 5s`),
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"cache_ttl": "15s"}},
			assert: func(t *testing.T, err error, prototype, configured *genericAuthenticator) {
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
				assert.Equal(t, prototype.sessionLifespanConf, configured.sessionLifespanConf)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.Equal(t, "prototype config with cache ttl, config with cache tll", configured.ID())
				assert.Equal(t, prototype.principalName, configured.principalName)
			},
		},
		"prototype with session lifespan config and empty target config": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
forward_cookies:
  - foo-cookie
payload: |
  foo=bar
principal:
  id: some_template
cache_ttl: 5s
session_lifespan:
  active: foo
  issued_at: bar
  not_before: baz
  not_after: zab
  time_format: foo bar
  validity_leeway: 2s`),
			assert: func(t *testing.T, err error, prototype, configured *genericAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.payload, configured.payload)
				assert.Equal(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Equal(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, prototype.sessionLifespanConf, configured.sessionLifespanConf)
				assert.NotNil(t, configured.sessionLifespanConf)
				assert.Equal(t, "foo", configured.sessionLifespanConf.ActiveField)
				assert.Equal(t, "bar", configured.sessionLifespanConf.IssuedAtField)
				assert.Equal(t, "baz", configured.sessionLifespanConf.NotBeforeField)
				assert.Equal(t, "zab", configured.sessionLifespanConf.NotAfterField)
				assert.Equal(t, "foo bar", configured.sessionLifespanConf.TimeFormat)
				assert.Equal(t, 2*time.Second, configured.sessionLifespanConf.ValidityLeeway)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.Equal(t, "prototype with session lifespan config and empty target config", configured.ID())
				assert.Equal(t, prototype.principalName, configured.principalName)
			},
		},
		"reconfiguration of identity_info_endpoint not possible": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
principal:
  id: some_template`),
			stepDef: types.StepDefinition{Config: config.MechanismConfig{
				"identity_info_endpoint": map[string]any{"url": "http://foo.bar"},
			}},
			assert: func(t *testing.T, err error, _, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"reconfiguration of authentication_data_source not possible": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
principal:
  id: some_template`),
			stepDef: types.StepDefinition{Config: config.MechanismConfig{
				"authentication_data_source": []any{map[string]any{"header": "bar-header"}},
			}},
			assert: func(t *testing.T, err error, _, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"reconfiguration of principal not possible": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
principal:
  id: some_template`),
			stepDef: types.StepDefinition{Config: config.MechanismConfig{
				"principal": map[string]any{"id": "new_template"},
			}},
			assert: func(t *testing.T, err error, _, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"reconfiguration of session_lifespan not possible": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
principal:
  id: some_template`),
			stepDef: types.StepDefinition{Config: config.MechanismConfig{
				"session_lifespan": map[string]any{"active": "foo"},
			}},
			assert: func(t *testing.T, err error, _, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"reconfiguration of payload not possible": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
principal:
  id: some_template`),
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"payload": "foo=bar"}},
			assert: func(t *testing.T, err error, _, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"reconfiguration of header to be forwarded not possible": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
principal:
  id: some_template`),
			stepDef: types.StepDefinition{Config: config.MechanismConfig{
				"forward_headers": []string{"foo-bar"},
			}},
			assert: func(t *testing.T, err error, _, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"reconfiguration of cookies to be forwarded not possible": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
principal:
  id: some_template`),
			stepDef: types.StepDefinition{Config: config.MechanismConfig{
				"forward_cookies": []string{"foo-bar"},
			}},
			assert: func(t *testing.T, err error, _, _ *genericAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"minimal valid prototype config and step ID configured": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
authentication_data_source:
  - header: foo-header
forward_headers:
  - X-My-Header
principal:
  id: some_template`),
			stepDef: types.StepDefinition{ID: "foo"},
			assert: func(t *testing.T, err error, prototype, configured *genericAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.payload, configured.payload)
				assert.Equal(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Equal(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.Equal(t, time.Duration(0), prototype.ttl)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, 0*time.Second, configured.ttl)
				assert.Equal(t, prototype.sessionLifespanConf, configured.sessionLifespanConf)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, prototype.Name(), prototype.ID())
				assert.Equal(t, "minimal valid prototype config and step ID configured", prototype.Name())
				assert.Equal(t, "foo", configured.ID())
				assert.Equal(t, prototype.principalName, configured.principalName)
			},
		},
		"minimal valid prototype config and principal name configured": {
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
authentication_data_source:
  - header: foo-header
forward_headers:
  - X-My-Header
principal:
  id: some_template`),
			stepDef: types.StepDefinition{Principal: "foo"},
			assert: func(t *testing.T, err error, prototype, configured *genericAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.ads, configured.ads)
				assert.Equal(t, prototype.payload, configured.payload)
				assert.Equal(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Equal(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Equal(t, prototype.sf, configured.sf)
				assert.Equal(t, time.Duration(0), prototype.ttl)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, 0*time.Second, configured.ttl)
				assert.Equal(t, prototype.sessionLifespanConf, configured.sessionLifespanConf)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, prototype.Name(), prototype.ID())
				assert.Equal(t, "minimal valid prototype config and principal name configured", prototype.Name())
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.NotEqual(t, prototype.principalName, configured.principalName)
				assert.Equal(t, "foo", configured.principalName)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			pc, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			validator, err := validation.NewValidator(
				validation.WithTagValidator(config.EnforcementSettings{}),
			)
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			mech, err := newGenericAuthenticator(appCtx, uc, pc)
			require.NoError(t, err)

			configured, ok := mech.(*genericAuthenticator)
			require.True(t, ok)

			// WHEN
			step, err := mech.CreateStep(tc.stepDef)

			// THEN
			auth, ok := step.(*genericAuthenticator)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, configured, auth)
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
		assert func(t *testing.T, err error, sub identity.Subject)
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
			assert: func(t *testing.T, err error, _ identity.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.ErrorContains(t, err, "failed to get authentication data")

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
			assert: func(t *testing.T, err error, _ identity.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed to render payload")

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
			assert: func(t *testing.T, err error, _ identity.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed to render URL")

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
			assert: func(t *testing.T, err error, _ identity.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrCommunication)
				require.ErrorContains(t, err, "request to the endpoint")

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
			assert: func(t *testing.T, err error, _ identity.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrCommunication)
				require.ErrorContains(t, err, "unexpected response code")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "auth3", identifier.ID())
			},
		},
		"with error while extracting principal information": {
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
				sf: &PrincipalInfo{IDFrom: "barfoo"},
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
			assert: func(t *testing.T, err error, _ identity.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed to extract principal")

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
				sf: &PrincipalInfo{IDFrom: "user_id"},
				payload: func() template.Template {
					tpl, err := template.New("foo={{ .AuthenticationData }}")
					require.NoError(t, err)

					return tpl
				}(),
				principalName: "default",
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
			assert: func(t *testing.T, err error, sub identity.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "barbar", sub.ID())
				assert.Len(t, sub.Attributes(), 1)
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
				sf:            &PrincipalInfo{IDFrom: "user_id"},
				ttl:           5 * time.Second,
				principalName: "default",
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
			assert: func(t *testing.T, err error, sub identity.Subject) {
				t.Helper()

				assert.False(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "barbar", sub.ID())
				assert.Len(t, sub.Attributes(), 1)
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
				sf:            &PrincipalInfo{IDFrom: "user_id"},
				fwdHeaders:    []string{"X-Original-Auth"},
				ttl:           5 * time.Second,
				principalName: "default",
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
			assert: func(t *testing.T, err error, sub identity.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "barbar", sub.ID())
				assert.Len(t, sub.Attributes(), 1)
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
				sf:                  &PrincipalInfo{IDFrom: "user_id"},
				fwdCookies:          []string{"original-auth"},
				ttl:                 5 * time.Second,
				sessionLifespanConf: &SessionLifespanConfig{ActiveField: "active"},
				principalName:       "default",
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
			assert: func(t *testing.T, err error, _ identity.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.ErrorContains(t, err, "not active")

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
				sf:                  &PrincipalInfo{IDFrom: "user_id"},
				ttl:                 5 * time.Second,
				sessionLifespanConf: &SessionLifespanConfig{IssuedAtField: "iat"},
				principalName:       "default",
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
			assert: func(t *testing.T, err error, _ identity.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed parsing issued_at")

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
				sf:                  &PrincipalInfo{IDFrom: "user_id"},
				ttl:                 30 * time.Second,
				sessionLifespanConf: &SessionLifespanConfig{NotAfterField: "exp"},
				principalName:       "default",
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
			assert: func(t *testing.T, err error, sub identity.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Equal(t, "barbar", sub.ID())
				assert.Len(t, sub.Attributes(), 2)
			},
		},
		"execution with custom principal": {
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
				sf:            &PrincipalInfo{IDFrom: "user_id"},
				ttl:           30 * time.Second,
				principalName: "foo",
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
				cch.EXPECT().Set(mock.Anything, mock.Anything, []byte(`{ "user_id": "barbar", "exp": `+exp+` }`), 30*time.Second).Return(nil)
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
			assert: func(t *testing.T, err error, sub identity.Subject) {
				t.Helper()

				assert.True(t, endpointCalled)

				require.NoError(t, err)

				require.NotNil(t, sub)
				assert.Empty(t, sub.ID())
				assert.Empty(t, sub.Attributes())
				assert.NotNil(t, sub["foo"])
				assert.Equal(t, "barbar", sub["foo"].ID)
				assert.Len(t, sub["foo"].Attributes, 2)
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
			ctx.EXPECT().Context().Return(cache.WithContext(t.Context(), cch))

			configureMocks(t, ctx, cch, ads, tc.authenticator)
			instructServer(t)

			sub := make(identity.Subject)

			// WHEN
			err := tc.authenticator.Execute(ctx, sub)

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

func TestGenericAuthenticatorKind(t *testing.T) {
	t.Parallel()

	// GIVEN
	auth := genericAuthenticator{}

	// WHEN & THEN
	require.Equal(t, types.KindAuthenticator, auth.Kind())
}

func TestGenericAuthenticatorReadResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status int
		err    error
	}{
		{http.StatusOK, nil},
		{http.StatusUnauthorized, heimdall.ErrAuthentication},
		{http.StatusForbidden, heimdall.ErrAuthentication},
		{http.StatusBadGateway, heimdall.ErrCommunication},
	}

	for _, tc := range tests {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			// GIVEN
			auth := &genericAuthenticator{}
			resp := &http.Response{
				StatusCode: tc.status,
				Body:       io.NopCloser(bytes.NewBufferString("{}")),
			}

			// WHEN
			_, err := auth.readResponse(resp)

			// THEN
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
