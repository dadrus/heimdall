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

package httpendpoint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x"
	otelmock "github.com/dadrus/heimdall/internal/x/opentelemetry/mocks"
)

func TestRuleSetEndpointInit(t *testing.T) {
	t.Parallel()

	// GIVEN
	ep := &ruleSetEndpoint{Endpoint: endpoint.Endpoint{URL: "http://foo.bar"}}

	// WHEN
	ep.init()

	// THEN
	assert.Equal(t, "http://foo.bar", ep.URL)
	assert.Equal(t, http.MethodGet, ep.Method)
	require.NotNil(t, ep.HTTPCache)
	assert.True(t, ep.HTTPCache.Enabled)
}

func TestRuleSetEndpointFetchRuleSet(t *testing.T) {
	t.Parallel()

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	otel.SetTracerProvider(otelmock.NewMockTraceProvider())

	type ResponseWriter func(t *testing.T, w http.ResponseWriter)

	var writeResponse ResponseWriter

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NotEmpty(t, r.Header.Get("Traceparent"))

		writeResponse(t, w)
	}))

	defer srv.Close()

	for _, tc := range []struct {
		uc            string
		ep            *ruleSetEndpoint
		writeResponse ResponseWriter
		assert        func(t *testing.T, err error, ruleSet *config.RuleSet)
	}{
		{
			uc: "rule set loading error due to DNS error",
			ep: &ruleSetEndpoint{
				Endpoint: endpoint.Endpoint{
					URL:    "https://foo.bar.local/rules.yaml",
					Method: http.MethodGet,
				},
			},
			assert: func(t *testing.T, err error, _ *config.RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "endpoint failed")
			},
		},
		{
			uc: "rule set loading error due to server error response",
			ep: &ruleSetEndpoint{
				Endpoint: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
				},
			},
			writeResponse: func(t *testing.T, w http.ResponseWriter) {
				t.Helper()

				w.WriteHeader(http.StatusBadRequest)
			},
			assert: func(t *testing.T, err error, _ *config.RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "response code: 400")
			},
		},
		{
			uc: "rule set loading error due to not set Content-Type for a not empty body",
			ep: &ruleSetEndpoint{
				Endpoint: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
				},
			},
			writeResponse: func(t *testing.T, w http.ResponseWriter) {
				t.Helper()

				_, err := w.Write([]byte(`
version: "1"
name: test
rules:
- id: bar
  match:
    routes: 
      - path: /bar
`))
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, _ *config.RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "content type")
			},
		},
		{
			uc: "empty rule set is returned on response with empty body",
			ep: &ruleSetEndpoint{
				Endpoint: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
				},
			},
			writeResponse: func(t *testing.T, w http.ResponseWriter) {
				t.Helper()

				w.WriteHeader(http.StatusOK)
			},
			assert: func(t *testing.T, err error, _ *config.RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, config.ErrEmptyRuleSet)
			},
		},
		{
			uc: "valid rule set without path prefix from yaml",
			ep: &ruleSetEndpoint{
				Endpoint: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
				},
			},
			writeResponse: func(t *testing.T, w http.ResponseWriter) {
				t.Helper()

				w.Header().Set("Content-Type", "application/yaml")
				_, err := w.Write([]byte(`
version: "1"
name: test
rules:
- id: foo
  match:
    routes:
      - path: /foo/:bar
        path_params:
          - name: bar
            type: glob
            value: "*baz"
    methods: [ GET ]
  execute:
   - authenticator: test
`))
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSet *config.RuleSet) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, ruleSet)
				assert.Equal(t, "test", ruleSet.Name)
				assert.Equal(t, "1", ruleSet.Version)
				assert.Len(t, ruleSet.Rules, 1)
				assert.Equal(t, "foo", ruleSet.Rules[0].ID)
				require.Len(t, ruleSet.Rules[0].Matcher.Routes, 1)
				assert.Equal(t, "/foo/:bar", ruleSet.Rules[0].Matcher.Routes[0].Path)
				require.Len(t, ruleSet.Rules[0].Matcher.Routes[0].PathParams, 1)
				assert.Equal(t, "bar", ruleSet.Rules[0].Matcher.Routes[0].PathParams[0].Name)
				assert.Equal(t, "glob", ruleSet.Rules[0].Matcher.Routes[0].PathParams[0].Type)
				assert.Equal(t, "*baz", ruleSet.Rules[0].Matcher.Routes[0].PathParams[0].Value)
				assert.Equal(t, []string{"GET"}, ruleSet.Rules[0].Matcher.Methods)
				assert.NotEmpty(t, ruleSet.Hash)
			},
		},
		{
			uc: "valid rule set without path prefix from json",
			ep: &ruleSetEndpoint{
				Endpoint: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
				},
			},
			writeResponse: func(t *testing.T, w http.ResponseWriter) {
				t.Helper()

				w.Header().Set("Content-Type", "application/json")
				_, err := w.Write([]byte(`{ 
	"version": "1",
	"name": "test",
	"rules": [
		{ 
          "id": "foo",
          "match": { 
            "routes": [{"path": "/foo"}],
            "methods" : ["GET"]
          },
          "execute": [{ "authenticator": "test"}] }
	]
}`))
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSet *config.RuleSet) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, ruleSet)
				assert.Len(t, ruleSet.Rules, 1)
				assert.Equal(t, "foo", ruleSet.Rules[0].ID)
				require.NotEmpty(t, ruleSet.Hash)
			},
		},
		{
			uc: "valid rule set with full url glob",
			ep: &ruleSetEndpoint{
				Endpoint: endpoint.Endpoint{
					URL:    srv.URL,
					Method: http.MethodGet,
				},
			},
			writeResponse: func(t *testing.T, w http.ResponseWriter) {
				t.Helper()

				w.Header().Set("Content-Type", "application/json")
				_, err := w.Write([]byte(`{ 
	"version": "1",
	"name": "test",
	"rules": [
      { 
	    "id": "foo",
        "match": {
          "routes": [
            { "path": "/foo/bar/:baz", "path_params": [{ "name": "baz", "type":"glob", "value":"{*.ico,*.js}" }] }
          ],
          "methods": [ "GET" ],
          "hosts": [{ "value":"moobar.local:9090", "type": "exact"}],
	    },
        "execute": [{ "authenticator": "test"}]
	  }
	]
}`))
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSet *config.RuleSet) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, ruleSet)
				assert.Len(t, ruleSet.Rules, 1)
				assert.Equal(t, "foo", ruleSet.Rules[0].ID)
				require.NotEmpty(t, ruleSet.Hash)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			validator, err := validation.NewValidator()
			require.NoError(t, err)

			cch := mocks.NewCacheMock(t)
			ctx := log.Logger.With().
				Str("_provider_type", "http_endpoint").
				Logger().
				WithContext(cache.WithContext(context.Background(), cch))

			writeResponse = x.IfThenElse(tc.writeResponse != nil,
				tc.writeResponse,
				func(t *testing.T, w http.ResponseWriter) {
					t.Helper()

					w.WriteHeader(http.StatusOK)
				})

			// WHEN
			ruleSet, err := tc.ep.FetchRuleSet(ctx, validator)

			// THEN
			tc.assert(t, err, ruleSet)
		})
	}
}
