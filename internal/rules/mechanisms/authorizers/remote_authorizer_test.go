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

package authorizers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	pipelinemocks "github.com/dadrus/heimdall/internal/pipeline/mocks"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	endpointmocks "github.com/dadrus/heimdall/internal/rules/endpoint/mocks"
	endpointtestsupport "github.com/dadrus/heimdall/internal/rules/endpoint/testsupport"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/cellib"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/values"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewRemoteAuthorizer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		enforceTLS bool
		config     []byte
		assert     func(t *testing.T, err error, auth *remoteAuthorizer)
	}{
		"configuration with unknown properties": {
			config: []byte(`
endpoint:
  url: http://foo.bar
foo: bar
`),
			assert: func(t *testing.T, err error, _ *remoteAuthorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"configuration with invalid endpoint config": {
			config: []byte(`
endpoint:
  method: FOO
payload: FooBar
`),
			assert: func(t *testing.T, err error, _ *remoteAuthorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "'endpoint'.'url' is a required field")
			},
		},
		"configuration without both payload and header": {
			config: []byte(`
endpoint:
  url: http://foo.bar
`),
			assert: func(t *testing.T, err error, _ *remoteAuthorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "'payload' is a required field")
			},
		},
		"minimal valid configuration with enforced and used TLS": {
			enforceTLS: true,
			config: []byte(`
endpoint:
  url: https://foo.bar
payload: "{{ .Subject.ID }}"
`),
			assert: func(t *testing.T, err error, auth *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, auth)
				require.NotNil(t, auth.payload)
				val, err := auth.payload.Render(map[string]any{
					"Subject": pipeline.Subject{"default": &pipeline.Principal{ID: "bar"}},
				})
				require.NoError(t, err)
				assert.Equal(t, "bar", val)
				assert.Zero(t, auth.ttl)

				assert.Equal(t, "minimal valid configuration with enforced and used TLS", auth.ID())
				assert.Equal(t, auth.ID(), auth.Name())

				assert.Equal(t, types.KindAuthorizer, auth.Kind())
				assert.Equal(t, auth.ID(), auth.Type())
			},
		},
		"minimal configuration with enforced but not used TLS": {
			enforceTLS: true,
			config: []byte(`
endpoint:
  url: http://foo.bar
payload: "{{ .Subject.ID }}"
`),
			assert: func(t *testing.T, err error, _ *remoteAuthorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "'endpoint'.'url' scheme must be https")
			},
		},
		"configuration with endpoint and endpoint header": {
			config: []byte(`
endpoint:
  url: http://foo.bar
  headers:
    X-My-Header: Foo
`),
			assert: func(t *testing.T, err error, auth *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, auth)
				require.Equal(t, "Foo", auth.e.Headers["X-My-Header"].String())
				assert.Nil(t, auth.payload)
				assert.Zero(t, auth.ttl)

				assert.Equal(t, "configuration with endpoint and endpoint header", auth.ID())
				assert.Equal(t, auth.ID(), auth.Name())

				assert.Equal(t, types.KindAuthorizer, auth.Kind())
				assert.Equal(t, auth.ID(), auth.Type())
			},
		},
		"configuration with invalid expression": {
			config: []byte(`
endpoint:
  url: http://foo.bar
payload: "{{ .Subject.ID }}"
expressions:
  - expression: "foo == 'bar'"
`),
			assert: func(t *testing.T, err error, _ *remoteAuthorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed to compile")
			},
		},
		"full configuration": {
			config: []byte(`
endpoint:
  url: http://foo.bar/test
payload: "{{ .Subject.ID }}: {{ splitList \"/\" .Request.URL.Path | atIndex -1 }}"
expressions:
  - expression: "Payload.foo == 'bar'"
cache_ttl: 5s
values:
  foo: "{{ .Subject.ID }}"
`),
			assert: func(t *testing.T, err error, auth *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				ctx := pipelinemocks.NewContextMock(t)
				ctx.EXPECT().Context().Return(t.Context()).Maybe()

				rfunc := pipelinemocks.NewRequestFunctionsMock(t)

				require.NotNil(t, auth)
				require.NotNil(t, auth.payload)
				val, err := auth.payload.Render(map[string]any{
					"Subject": pipeline.Subject{"default": &pipeline.Principal{ID: "bar"}},
					"Request": &pipeline.Request{
						RequestFunctions: rfunc,
						URL:              &pipeline.URL{URL: url.URL{Scheme: "http", Host: "foo.bar", Path: "/foo/bar"}},
					},
				})
				require.NoError(t, err)
				require.NotEmpty(t, auth.expressions)
				err = auth.expressions.eval(map[string]any{
					"Payload": map[string]any{"foo": "bar"},
				}, auth)
				require.NoError(t, err)
				assert.Equal(t, "bar: bar", val)
				assert.NotNil(t, auth.ttl)
				assert.Equal(t, 5*time.Second, auth.ttl)

				res, err := auth.v.Render(map[string]any{
					"Subject": pipeline.Subject{"default": &pipeline.Principal{ID: "bar"}},
				})
				require.NoError(t, err)
				assert.Equal(t, map[string]string{"foo": "bar"}, res)

				assert.Equal(t, "full configuration", auth.ID())
				assert.Equal(t, auth.ID(), auth.Name())

				assert.Equal(t, types.KindAuthorizer, auth.Kind())
				assert.Equal(t, auth.ID(), auth.Type())
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

			sr := secretsmocks.NewResolverMock(t)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().DecoderFactory().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))
			appCtx.EXPECT().Logger().Return(log.Logger)
			appCtx.EXPECT().SecretResolver().Return(sr)

			// WHEN
			mech, err := newRemoteAuthorizer(appCtx, uc, conf)

			// THEN
			auth, ok := mech.(*remoteAuthorizer)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, auth)
		})
	}
}

func TestRemoteAuthorizerCreateStep(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config  []byte
		stepDef types.StepDefinition
		assert  func(t *testing.T, err error, prototype, configured *remoteAuthorizer)
	}{
		"without new configuration and without step ID": {
			config: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			assert: func(t *testing.T, err error, prototype, configured *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
			},
		},
		"without new configuration but with step ID": {
			config: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			stepDef: types.StepDefinition{ID: "foo"},
			assert: func(t *testing.T, err error, prototype, configured *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.NotEqual(t, prototype.ID(), configured.ID())
				assert.Equal(t, "foo", configured.ID())
				assert.Equal(t, types.KindAuthorizer, configured.Kind())
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.payload, configured.payload)
				assert.Equal(t, prototype.expressions, configured.expressions)
				assert.NotNil(t, configured.ttl)
				assert.Equal(t, prototype.Type(), configured.Type())
			},
		},
		"with unknown properties in step configuration": {
			config: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"foo": "bar"}},
			assert: func(t *testing.T, err error, prototype, configured *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		"with malformed step configuration": {
			config: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"payload": 1}},
			assert: func(t *testing.T, err error, _, _ *remoteAuthorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"with overridden empty payload": {
			config: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			stepDef: types.StepDefinition{
				Config: config.MechanismConfig{
					"payload":   "",
					"cache_ttl": "1s",
				},
			},
			assert: func(t *testing.T, err error, prototype, configured *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.NotNil(t, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.NotEqual(t, prototype.payload, configured.payload)
				assert.Equal(t, prototype.expressions, configured.expressions)
				assert.NotNil(t, configured.ttl)
				assert.Equal(t, "with overridden empty payload", configured.ID())
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, types.KindAuthorizer, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
			},
		},
		"with new config and step id": {
			config: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			stepDef: types.StepDefinition{
				ID:     "foo",
				Config: config.MechanismConfig{"cache_ttl": "1s"},
			},
			assert: func(t *testing.T, err error, prototype, configured *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.NotNil(t, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.payload, configured.payload)
				assert.Equal(t, prototype.expressions, configured.expressions)
				assert.Equal(t, 1*time.Second, configured.ttl)
				assert.Equal(t, "foo", configured.ID())
				assert.NotEqual(t, prototype.ID(), configured.ID())
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, types.KindAuthorizer, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
			},
		},
		"with invalid new expression": {
			config: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			stepDef: types.StepDefinition{
				Config: config.MechanismConfig{
					"expressions": []map[string]any{
						{"expression": "foo == 'bar'"},
					},
				},
			},
			assert: func(t *testing.T, err error, _, _ *remoteAuthorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed to compile")
			},
		},
		"with everything possible, but values reconfigured": {
			config: []byte(`
endpoint:
  url: http://foo.bar
  headers:
    Foo: Bar
values:
  foo: bar
`),
			stepDef: types.StepDefinition{
				Config: config.MechanismConfig{
					"payload": "Baz",
					"expressions": []map[string]any{
						{"expression": "Payload.foo == 'bar'"},
					},
					"cache_ttl": "15s",
				},
			},
			assert: func(t *testing.T, err error, prototype, configured *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.NotNil(t, configured)
				assert.Equal(t, prototype.e, configured.e)
				require.NotNil(t, configured.payload)

				val, err := configured.payload.Render(nil)
				require.NoError(t, err)

				assert.Empty(t, prototype.expressions)
				require.NotEmpty(t, configured.expressions)

				err = configured.expressions.eval(map[string]any{
					"Payload": map[string]any{"foo": "bar"},
				}, configured)
				require.NoError(t, err)

				assert.Equal(t, "Baz", val)
				assert.Equal(t, 15*time.Second, configured.ttl)

				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, prototype.v, configured.v)
				assert.NotEqual(t, prototype.payload, configured.payload)
				assert.Equal(t, "with everything possible, but values reconfigured", configured.ID())
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, types.KindAuthorizer, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
			},
		},
		"with everything possible": {
			config: []byte(`
endpoint:
  url: http://foo.bar
  headers:
    Foo: Bar
values:
  foo: bar
`),
			stepDef: types.StepDefinition{
				Config: config.MechanismConfig{
					"values":  map[string]any{"bar": "foo"},
					"payload": "Baz",
					"expressions": []map[string]any{
						{"expression": "Payload.foo == 'bar'"},
					},
					"cache_ttl": "15s",
				},
			},
			assert: func(t *testing.T, err error, prototype, configured *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.NotNil(t, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.e.URL, configured.e.URL)
				assert.Equal(t, prototype.e.Headers, configured.e.Headers)
				assert.NotEqual(t, prototype.v, configured.v)

				res, err := configured.v.Render(map[string]any{})
				require.NoError(t, err)
				assert.Equal(t, map[string]string{"bar": "foo", "foo": "bar"}, res)

				require.NotNil(t, configured.payload)

				val, err := configured.payload.Render(nil)
				require.NoError(t, err)

				assert.Empty(t, prototype.expressions)
				require.NotEmpty(t, configured.expressions)

				err = configured.expressions.eval(map[string]any{
					"Payload": map[string]any{"foo": "bar"},
				}, configured)
				require.NoError(t, err)

				assert.Equal(t, "Baz", val)
				assert.Equal(t, 15*time.Second, configured.ttl)

				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.NotEqual(t, prototype.payload, configured.payload)
				assert.Equal(t, "with everything possible", configured.ID())
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, types.KindAuthorizer, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
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

			sr := secretsmocks.NewResolverMock(t)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().DecoderFactory().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))
			appCtx.EXPECT().Logger().Return(log.Logger)
			appCtx.EXPECT().SecretResolver().Return(sr)

			mech, err := newRemoteAuthorizer(appCtx, uc, pc)
			require.NoError(t, err)

			configured, ok := mech.(*remoteAuthorizer)
			require.True(t, ok)

			// WHEN
			step, err := mech.CreateStep(sr, tc.stepDef)

			// THEN
			auth, ok := step.(*remoteAuthorizer)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, configured, auth)
		})
	}
}

func TestRemoteAuthorizerExecute(t *testing.T) {
	t.Parallel()

	var (
		authorizationEndpointCalled bool
		redirectEndpointCalled      bool
		checkRequest                func(req *http.Request)

		responseHeaders     map[string]string
		responseContentType string
		responseContent     []byte
		responseCode        int
	)

	env, err := cel.NewEnv(cellib.Library())
	require.NoError(t, err)

	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectEndpointCalled = true

		w.WriteHeader(http.StatusOK)
	}))
	defer redirectSrv.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizationEndpointCalled = true

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
		authorizer       *remoteAuthorizer
		subject          pipeline.Subject
		instructServer   func(t *testing.T)
		configureContext func(t *testing.T, ctx *pipelinemocks.ContextMock)
		configureCache   func(t *testing.T, cch *mocks.CacheMock, authorizer *remoteAuthorizer, sub pipeline.Subject)
		assert           func(t *testing.T, err error, sub pipeline.Subject, results pipeline.Results)
	}{
		"successful with payload and with header, without payload from server and with disabled cache": {
			authorizer: &remoteAuthorizer{
				id: "authorizer",
				e: endpointtestsupport.EndpointValue(t, srv.URL,
					endpoint.WithHeader("Foo-Bar", "{{ .Subject.Attributes.bar }}"),
				),
				v: func() values.Values {
					tpl, _ := template.New("bar")

					return values.Values{"foo": tpl}
				}(),
				payload: func() template.Template {
					tpl, _ := template.New("{{ .Subject.ID }}-{{ .Values.foo }}-{{ .Outputs.foo.Payload }}-{{ .Results.foo.Payload }}")

					return tpl
				}(),
			},
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "my-id",
					Attributes: map[string]any{"bar": "baz"},
				},
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				responseCode = http.StatusOK

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, http.MethodPost, req.Method)
					assert.Equal(t, "baz", req.Header.Get("Foo-Bar"))
					assert.Empty(t, req.Header.Get("Content-Type"))
					assert.Empty(t, req.Header.Get("Accept"))

					data, err := io.ReadAll(req.Body)
					require.NoError(t, err)

					assert.Equal(t, "my-id-bar-bar-bar", string(data))
				}
			},
			configureContext: func(t *testing.T, ctx *pipelinemocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error, sub pipeline.Subject, results pipeline.Results) {
				t.Helper()

				require.NoError(t, err)

				assert.True(t, authorizationEndpointCalled)
				assert.Len(t, sub.Attributes(), 1)
				assert.Equal(t, "baz", sub.Attributes()["bar"])

				assert.Len(t, results, 2)

				result := results["authorizer"]
				require.NotNil(t, result)
				assert.NotEmpty(t, result.Header("Date"))
				assert.NotEmpty(t, result.Header("Content-Length"))
				assert.Empty(t, result.Payload)
			},
		},
		"successful with json payload and with header from server and with disabled cache": {
			authorizer: &remoteAuthorizer{
				id: "authorizer",
				e: endpointtestsupport.EndpointValue(t, srv.URL,
					endpoint.WithHeader("Content-Type", "application/json"),
					endpoint.WithHeader("Accept", "application/json"),
					endpoint.WithHeader("Foo-Bar", "{{ .Subject.Attributes.bar }}"),
				),
				payload: func() template.Template {
					tpl, _ := template.New(`{ "user_id": {{ quote .Subject.ID }} }`)

					return tpl
				}(),
			},
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "my-id",
					Attributes: map[string]any{"bar": "baz"},
				},
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, http.MethodPost, req.Method)
					assert.Equal(t, "baz", req.Header.Get("Foo-Bar"))
					assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))

					data, err := io.ReadAll(req.Body)
					require.NoError(t, err)

					var mapData map[string]string

					err = json.Unmarshal(data, &mapData)
					require.NoError(t, err)

					assert.Len(t, mapData, 1)
					assert.Equal(t, "my-id", mapData["user_id"])
				}

				responseCode = http.StatusOK

				rawData, err := json.Marshal(map[string]any{
					"access_granted": true,
					"permissions":    []string{"read_foo", "write_foo"},
					"groups":         []string{"Foo-Users"},
				})
				require.NoError(t, err)

				responseContent = rawData
				responseContentType = "application/json"
				responseHeaders = map[string]string{"X-Foo-Bar": "HeyFoo"}
			},
			configureContext: func(t *testing.T, ctx *pipelinemocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error, sub pipeline.Subject, results pipeline.Results) {
				t.Helper()

				require.NoError(t, err)

				assert.True(t, authorizationEndpointCalled)
				assert.Len(t, sub.Attributes(), 1)
				assert.Equal(t, "baz", sub.Attributes()["bar"])

				assert.Len(t, results, 2)

				result := results["authorizer"]
				require.NotNil(t, result)

				assert.NotEmpty(t, result.Header("Date"))
				assert.NotEmpty(t, result.Header("Content-Length"))
				assert.Equal(t, "application/json", result.Header("Content-Type"))
				assert.NotEmpty(t, result.Header("X-Foo-Bar"))

				payload, ok := result.Payload.(map[string]any)
				require.True(t, ok)

				assert.Len(t, payload, 3)
				assert.Contains(t, payload, "access_granted")
				assert.Contains(t, payload, "groups")
				assert.Contains(t, payload, "permissions")
			},
		},
		"successful with www-form-urlencoded payload and without header, without payload, but with headers from server " +
			"and with failing cache hit": {
			authorizer: &remoteAuthorizer{
				id: "authorizer",
				e: endpointtestsupport.EndpointValue(t, srv.URL,
					endpoint.WithHeader("Content-Type", "application/x-www-form-urlencoded"),
				),
				v: func() values.Values {
					tpl, _ := template.New("foo")

					return values.Values{"foo": tpl}
				}(),
				payload: func() template.Template {
					tpl, _ := template.New(`user_id={{ urlenc .Subject.ID }}&{{ .Subject.Attributes.bar }}={{ .Values.foo }}&{{ .Values.foo }}={{ .Outputs.foo.Payload }}`)

					return tpl
				}(),
				ttl: 20 * time.Second,
			},
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "my id",
					Attributes: map[string]any{"bar": "baz"},
				},
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, http.MethodPost, req.Method)
					assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))

					data, err := io.ReadAll(req.Body)
					require.NoError(t, err)

					formValues, err := url.ParseQuery(string(data))
					require.NoError(t, err)

					assert.Len(t, formValues, 3)
					assert.Equal(t, []string{"my id"}, formValues["user_id"])
					assert.Equal(t, []string{"foo"}, formValues["baz"])
					assert.Equal(t, []string{"bar"}, formValues["foo"])
				}

				responseCode = http.StatusOK
				responseHeaders = map[string]string{"X-Foo-Bar": "HeyFoo"}
			},
			configureContext: func(t *testing.T, ctx *pipelinemocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			configureCache: func(t *testing.T, cch *mocks.CacheMock, auth *remoteAuthorizer, _ pipeline.Subject) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, assert.AnError)
				cch.EXPECT().Set(mock.Anything, mock.Anything,
					mock.MatchedBy(func(data []byte) bool {
						var ai pipeline.Result

						err := json.Unmarshal(data, &ai)

						return err == nil && ai.Payload == nil && len(ai.Header("X-Foo-Bar")) != 0
					}), auth.ttl).Return(nil)
			},
			assert: func(t *testing.T, err error, sub pipeline.Subject, results pipeline.Results) {
				t.Helper()

				require.NoError(t, err)

				assert.True(t, authorizationEndpointCalled)
				assert.Len(t, sub.Attributes(), 1)
				assert.Equal(t, "baz", sub.Attributes()["bar"])

				assert.NotEmpty(t, results["authorizer"])
				assert.Equal(t, "HeyFoo", results["authorizer"].Header("X-Foo-Bar"))
			},
		},
		"successful without headers and payload and with cache": {
			authorizer: &remoteAuthorizer{
				name: "authorizer",
				id:   "authorizer",
				e: endpointtestsupport.EndpointValue(t, srv.URL+"/{{ .Subject.ID }}",
					endpoint.WithHeader("Accept", "application/x-www-form-urlencoded"),
				),
				ttl: 10 * time.Second,
			},
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "foobar",
					Attributes: map[string]any{"bar": "baz"},
				},
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, http.MethodPost, req.Method)
					assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Accept"))
					assert.True(t, strings.HasSuffix(req.URL.Path, "/foobar"))
				}

				responseCode = http.StatusOK
			},
			configureContext: func(t *testing.T, ctx *pipelinemocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			configureCache: func(t *testing.T, cch *mocks.CacheMock, auth *remoteAuthorizer, _ pipeline.Subject) {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					srv.URL+"/foobar",
					nil,
				)
				require.NoError(t, err)

				req.Header.Set("Accept", "application/x-www-form-urlencoded")

				cacheKey := auth.calculateCacheKey(req, "")

				cch.EXPECT().Get(mock.Anything, cacheKey).Return(nil, assert.AnError)
				cch.EXPECT().Set(mock.Anything, cacheKey, mock.Anything, auth.ttl).Return(nil)
			},
			assert: func(t *testing.T, err error, sub pipeline.Subject, results pipeline.Results) {
				t.Helper()

				require.NoError(t, err)

				assert.True(t, authorizationEndpointCalled)
				assert.Len(t, sub.Attributes(), 1)
				assert.Equal(t, "baz", sub.Attributes()["bar"])

				assert.NotEmpty(t, results["authorizer"])
			},
		},
		"successfully reuse cache": {
			authorizer: &remoteAuthorizer{
				id: "authorizer",
				e: endpointtestsupport.EndpointValue(t, srv.URL,
					endpoint.WithHeader("Content-Type", "application/x-www-form-urlencoded"),
					endpoint.WithHeader("Foo-Bar", "{{ .Subject.Attributes.bar }}"),
				),
				payload: func() template.Template {
					tpl, _ := template.New(`user_id={{ urlenc .Subject.ID }}&{{ urlenc .Subject.Attributes.bar }}=foo`)

					return tpl
				}(),
				ttl: 20 * time.Second,
			},
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "my id",
					Attributes: map[string]any{"bar": "baz"},
				},
			},
			configureContext: func(t *testing.T, ctx *pipelinemocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			configureCache: func(t *testing.T, cch *mocks.CacheMock, _ *remoteAuthorizer, _ pipeline.Subject) {
				t.Helper()

				result := pipeline.NewResultWithHeaders(
					map[string]any{"foo": "bar"},
					http.Header{
						"X-Foo-Bar": {"HeyFoo"},
						"X-Bar-Foo": {"HeyBar"},
					},
				)

				rawInfo, err := json.Marshal(result)
				require.NoError(t, err)

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(rawInfo, nil)
			},
			assert: func(t *testing.T, err error, sub pipeline.Subject, results pipeline.Results) {
				t.Helper()

				require.NoError(t, err)

				assert.False(t, authorizationEndpointCalled)
				assert.Len(t, sub.Attributes(), 1)
				assert.Equal(t, "baz", sub.Attributes()["bar"])

				result := results["authorizer"]
				require.NotNil(t, result)

				assert.Equal(t, map[string]any{"foo": "bar"}, result.Payload)
				assert.Equal(t, "HeyFoo", result.Header("X-Foo-Bar"))
				assert.Equal(t, "HeyBar", result.Header("X-Bar-Foo"))
			},
		},
		"with failed authorization": {
			authorizer: &remoteAuthorizer{
				id: "authz",
				e: endpointtestsupport.EndpointValue(t, srv.URL,
					endpoint.WithHeader("X-User-ID", "{{ .Subject.ID }}"),
				),
			},
			subject: pipeline.Subject{
				"default": &pipeline.Principal{ID: "foo"},
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					assert.Equal(t, "foo", req.Header.Get("X-User-ID"))
				}

				responseCode = http.StatusUnauthorized
			},
			configureContext: func(t *testing.T, ctx *pipelinemocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error, _ pipeline.Subject, _ pipeline.Results) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrAuthorization)
				require.ErrorContains(t, err, "authorization failed")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)

				assert.Equal(t, "authz", identifier.ID())
			},
		},
		"with redirect response": {
			authorizer: &remoteAuthorizer{
				id: "authz",
				e:  endpointtestsupport.EndpointValue(t, srv.URL),
			},
			subject: pipeline.Subject{
				"default": &pipeline.Principal{ID: "foo"},
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				responseHeaders = map[string]string{
					"Location": redirectSrv.URL,
				}
				responseCode = http.StatusFound
			},
			configureContext: func(t *testing.T, ctx *pipelinemocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error, _ pipeline.Subject, _ pipeline.Results) {
				t.Helper()

				assert.True(t, authorizationEndpointCalled)
				assert.False(t, redirectEndpointCalled)

				require.Error(t, err)

				require.ErrorIs(t, err, pipeline.ErrAuthorization)
				require.ErrorContains(t, err, "authorization failed")
				require.ErrorContains(t, err, strconv.Itoa(http.StatusFound))

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)

				assert.Equal(t, "authz", identifier.ID())
			},
		},
		"with unsupported response content type": {
			authorizer: &remoteAuthorizer{
				id: "foo",
				e: endpointtestsupport.EndpointValue(t, srv.URL,
					endpoint.WithHeader("X-User-ID", "{{ .Subject.ID }}"),
				),
			},
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "foo",
					Attributes: map[string]any{},
				},
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				responseContent = []byte("Hi Foo")
				responseContentType = "text/text"
				responseCode = http.StatusOK
			},
			configureContext: func(t *testing.T, ctx *pipelinemocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error, sub pipeline.Subject, results pipeline.Results) {
				t.Helper()

				require.NoError(t, err)

				assert.True(t, authorizationEndpointCalled)
				assert.Empty(t, sub.Attributes())

				result := results["foo"]
				require.NotNil(t, result)
				assert.Equal(t, "Hi Foo", result.Payload)
			},
		},
		"with communication error (dns)": {
			authorizer: &remoteAuthorizer{
				id: "authz",
				e:  endpointtestsupport.EndpointValue(t, "http://heimdall.test.local"),
				payload: func() template.Template {
					tpl, _ := template.New("bar")

					return tpl
				}(),
			},
			subject: pipeline.Subject{
				"default": &pipeline.Principal{ID: "foo"},
			},
			configureContext: func(t *testing.T, ctx *pipelinemocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error, _ pipeline.Subject, _ pipeline.Results) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrCommunication)
				require.ErrorContains(t, err, "endpoint failed")

				assert.False(t, authorizationEndpointCalled)

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)

				assert.Equal(t, "authz", identifier.ID())
			},
		},
		"with expression, which returns false": {
			authorizer: &remoteAuthorizer{
				id: "authz",
				e: endpointtestsupport.EndpointValue(t, srv.URL,
					endpoint.WithHeader("Content-Type", "application/json"),
					endpoint.WithHeader("Accept", "application/json"),
				),
				payload: func() template.Template {
					tpl, _ := template.New(`{ "user_id": {{ quote .Subject.ID }} }`)

					return tpl
				}(),
				expressions: func() []*cellib.CompiledExpression {
					exp, err := cellib.CompileExpression(env, "false == true", "false != true")
					require.NoError(t, err)

					return []*cellib.CompiledExpression{exp}
				}(),
			},
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "my-id",
					Attributes: map[string]any{},
				},
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, http.MethodPost, req.Method)
					assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))

					data, err := io.ReadAll(req.Body)
					require.NoError(t, err)

					var mapData map[string]string

					err = json.Unmarshal(data, &mapData)
					require.NoError(t, err)

					assert.Len(t, mapData, 1)
					assert.Equal(t, "my-id", mapData["user_id"])
				}

				responseCode = http.StatusOK

				rawData, err := json.Marshal(map[string]any{
					"access_granted": true,
					"permissions":    []string{"read_foo", "write_foo"},
					"groups":         []string{"Foo-Users"},
				})
				require.NoError(t, err)

				responseContent = rawData
				responseContentType = "application/json"
			},
			configureContext: func(t *testing.T, ctx *pipelinemocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error, _ pipeline.Subject, _ pipeline.Results) {
				t.Helper()

				assert.True(t, authorizationEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrAuthorization)
				require.ErrorContains(t, err, "false != true")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)

				assert.Equal(t, "authz", identifier.ID())
			},
		},
		"with expression, which succeeds": {
			authorizer: &remoteAuthorizer{
				id: "authorizer",
				e: endpointtestsupport.EndpointValue(t, srv.URL,
					endpoint.WithHeader("Content-Type", "application/json"),
					endpoint.WithHeader("Accept", "application/json"),
				),
				payload: func() template.Template {
					tpl, _ := template.New(`{ "user_id": {{ quote .Subject.ID }} }`)

					return tpl
				}(),
				expressions: func() []*cellib.CompiledExpression {
					exp, err := cellib.CompileExpression(env, "Payload.access_granted == true", "err")
					require.NoError(t, err)

					return []*cellib.CompiledExpression{exp}
				}(),
			},
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "my-id",
					Attributes: map[string]any{},
				},
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, http.MethodPost, req.Method)
					assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))

					data, err := io.ReadAll(req.Body)
					require.NoError(t, err)

					var mapData map[string]string

					err = json.Unmarshal(data, &mapData)
					require.NoError(t, err)

					assert.Len(t, mapData, 1)
					assert.Equal(t, "my-id", mapData["user_id"])
				}

				responseCode = http.StatusOK

				rawData, err := json.Marshal(map[string]any{
					"access_granted": true,
					"permissions":    []string{"read_foo", "write_foo"},
					"groups":         []string{"Foo-Users"},
				})
				require.NoError(t, err)

				responseContent = rawData
				responseContentType = "application/json"
			},
			configureContext: func(t *testing.T, ctx *pipelinemocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error, sub pipeline.Subject, results pipeline.Results) {
				t.Helper()

				assert.True(t, authorizationEndpointCalled)

				require.NoError(t, err)

				require.Empty(t, sub.Attributes())

				result := results["authorizer"]
				require.NotNil(t, result)

				payload, ok := result.Payload.(map[string]any)
				require.True(t, ok)

				assert.Equal(t, true, payload["access_granted"]) //nolint:testifylint
			},
		},
		"with payload rendering error": {
			authorizer: &remoteAuthorizer{
				id: "authorizer",
				e:  endpointtestsupport.EndpointValue(t, srv.URL),
				payload: func() template.Template {
					tpl, err := template.New("{{ len .foo }}")
					require.NoError(t, err)

					return tpl
				}(),
			},
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "Foo",
					Attributes: map[string]any{"bar": "baz"},
				},
			},
			configureContext: func(t *testing.T, ctx *pipelinemocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error, _ pipeline.Subject, _ pipeline.Results) {
				t.Helper()

				assert.False(t, authorizationEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "failed to render payload")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)

				assert.Equal(t, "authorizer", identifier.ID())
			},
		},
		"with error in values rendering": {
			authorizer: &remoteAuthorizer{
				id: "authorizer",
				e:  endpointtestsupport.EndpointValue(t, srv.URL),
				v: func() values.Values {
					tpl, err := template.New("{{ len .foo }}")
					require.NoError(t, err)

					return values.Values{"foo": tpl}
				}(),
			},
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "Foo",
					Attributes: map[string]any{"bar": "baz"},
				},
			},
			configureContext: func(t *testing.T, ctx *pipelinemocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error, _ pipeline.Subject, _ pipeline.Results) {
				t.Helper()

				assert.False(t, authorizationEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "failed to render values")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)

				assert.Equal(t, "authorizer", identifier.ID())
			},
		},
		"failed with positive cache hit due to authorization expression": {
			authorizer: &remoteAuthorizer{
				name: "authz",
				id:   "authz",
				e:    endpointtestsupport.EndpointValue(t, srv.URL),
				expressions: func() []*cellib.CompiledExpression {
					exp, err := cellib.CompileExpression(env, "Payload.role == 'admin'", "admin role required")
					require.NoError(t, err)

					return []*cellib.CompiledExpression{exp}
				}(),
				ttl: 20 * time.Second,
			},
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "my-id",
					Attributes: map[string]any{},
				},
			},
			configureContext: func(t *testing.T, ctx *pipelinemocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			configureCache: func(t *testing.T, cch *mocks.CacheMock, auth *remoteAuthorizer, _ pipeline.Subject) {
				t.Helper()

				result := pipeline.NewResult(
					map[string]any{"role": "user"},
				)

				rawInfo, err := json.Marshal(result)
				require.NoError(t, err)

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					srv.URL,
					nil,
				)
				require.NoError(t, err)

				cacheKey := auth.calculateCacheKey(req, "")

				cch.EXPECT().Get(mock.Anything, cacheKey).Return(rawInfo, nil)
			},
			assert: func(t *testing.T, err error, _ pipeline.Subject, results pipeline.Results) {
				t.Helper()

				assert.False(t, authorizationEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrAuthorization)
				require.ErrorContains(t, err, "admin role required")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)

				assert.Equal(t, "authz", identifier.ID())

				assert.NotContains(t, results, "authz")
			},
		},
		"with rendered endpoint header and cache miss due to different output": {
			authorizer: &remoteAuthorizer{
				name: "authorizer",
				id:   "authorizer",
				e: endpointtestsupport.EndpointValue(t, srv.URL,
					endpoint.WithMethod(http.MethodGet),
					endpoint.WithHeader(
						"X-Tenant-ID",
						"{{ .Outputs.foo.Payload }}",
					),
				),
				ttl: 5 * time.Second,
			},
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "Foo",
					Attributes: map[string]any{"bar": "baz"},
				},
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "bar", req.Header.Get("X-Tenant-ID"))
				}

				responseContentType = "application/json"
				responseContent = []byte(`{"tenant":"bar"}`)
				responseCode = http.StatusOK
			},
			configureContext: func(t *testing.T, ctx *pipelinemocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			configureCache: func(t *testing.T, cch *mocks.CacheMock, auth *remoteAuthorizer, _ pipeline.Subject) {
				t.Helper()

				previousReq, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodGet,
					srv.URL,
					nil,
				)
				require.NoError(t, err)

				previousReq.Header.Set("X-Tenant-ID", "tenant-a")

				currentReq, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodGet,
					srv.URL,
					nil,
				)
				require.NoError(t, err)

				currentReq.Header.Set("X-Tenant-ID", "bar")

				previousCacheKey := auth.calculateCacheKey(previousReq, "")
				currentCacheKey := auth.calculateCacheKey(currentReq, "")

				require.NotEqual(t, previousCacheKey, currentCacheKey)

				cch.EXPECT().Get(mock.Anything, currentCacheKey).Return(nil, assert.AnError)
				cch.EXPECT().Set(mock.Anything, currentCacheKey, mock.Anything, auth.ttl).Return(nil)
			},
			assert: func(t *testing.T, err error, sub pipeline.Subject, results pipeline.Results) {
				t.Helper()

				assert.True(t, authorizationEndpointCalled)

				require.NoError(t, err)
				assert.Len(t, sub.Attributes(), 1)

				require.Len(t, results, 2)

				result := results["authorizer"]
				require.NotNil(t, result)

				assert.Equal(t, map[string]any{"tenant": "bar"}, result.Payload)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			authorizationEndpointCalled = false
			redirectEndpointCalled = false
			responseHeaders = nil
			responseContentType = ""
			responseContent = nil

			checkRequest = func(*http.Request) { t.Helper() }

			instructServer := x.IfThenElse(
				tc.instructServer != nil,
				tc.instructServer,
				func(t *testing.T) { t.Helper() },
			)

			configureContext := x.IfThenElse(
				tc.configureContext != nil,
				tc.configureContext,
				func(t *testing.T, _ *pipelinemocks.ContextMock) {
					t.Helper()
				},
			)

			configureCache := x.IfThenElse(
				tc.configureCache != nil,
				tc.configureCache,
				func(t *testing.T, _ *mocks.CacheMock, _ *remoteAuthorizer, _ pipeline.Subject) {
					t.Helper()
				},
			)

			cch := mocks.NewCacheMock(t)

			ctx := pipelinemocks.NewContextMock(t)
			ctx.EXPECT().Context().Return(cache.WithContext(t.Context(), cch))
			ctx.EXPECT().Results().Return(pipeline.Results{"foo": pipeline.NewResult("bar")})

			configureContext(t, ctx)
			configureCache(t, cch, tc.authorizer, tc.subject)
			instructServer(t)

			// WHEN
			err = tc.authorizer.Execute(ctx, tc.subject)

			// THEN
			tc.assert(t, err, tc.subject, ctx.Results())
		})
	}
}

func TestRemoteAuthorizerCalculateCacheKey(t *testing.T) {
	t.Parallel()

	authStrategyA := endpointmocks.NewAuthenticationStrategyMock(t)
	authStrategyA.EXPECT().Hash().Return([]byte("strategy-a"))

	authStrategyB := endpointmocks.NewAuthenticationStrategyMock(t)
	authStrategyB.EXPECT().Hash().Return([]byte("strategy-b"))

	newAuthorizer := func(name string, id string, ttl time.Duration) *remoteAuthorizer {
		t.Helper()

		return &remoteAuthorizer{
			name: name,
			id:   id,
			ttl:  ttl,
		}
	}

	newRequest := func(method string, rawURL string, headers map[string]string) *http.Request {
		t.Helper()

		req, err := http.NewRequestWithContext(t.Context(), method, rawURL, nil)
		require.NoError(t, err)

		for name, value := range headers {
			req.Header.Set(name, value)
		}

		return req
	}

	for uc, tc := range map[string]struct {
		authorizer1 *remoteAuthorizer
		authorizer2 *remoteAuthorizer
		request1    *http.Request
		request2    *http.Request
		payload1    string
		payload2    string
		expectEqual bool
	}{
		"same effective request": {
			authorizer1: newAuthorizer(
				"authorizer",
				"authorizer",
				5*time.Second,
			),
			authorizer2: newAuthorizer(
				"authorizer",
				"authorizer",
				5*time.Second,
			),
			request1: newRequest(
				http.MethodPost,
				"https://example.com/authorize",
				map[string]string{
					"Content-Type": "application/json",
					"X-Tenant-ID":  "tenant-a",
				},
			),
			request2: newRequest(
				http.MethodPost,
				"https://example.com/authorize",
				map[string]string{
					"Content-Type": "application/json",
					"X-Tenant-ID":  "tenant-a",
				},
			),
			payload1:    `{"foo":"bar"}`,
			payload2:    `{"foo":"bar"}`,
			expectEqual: true,
		},
		"different step id": {
			authorizer1: newAuthorizer(
				"authorizer",
				"step-a",
				5*time.Second,
			),
			authorizer2: newAuthorizer(
				"authorizer",
				"step-b",
				5*time.Second,
			),
			request1: newRequest(
				http.MethodGet,
				"https://example.com/authorize",
				nil,
			),
			request2: newRequest(
				http.MethodGet,
				"https://example.com/authorize",
				nil,
			),
			expectEqual: true,
		},
		"different authorizer name": {
			authorizer1: newAuthorizer(
				"authorizer-a",
				"step",
				5*time.Second,
			),
			authorizer2: newAuthorizer(
				"authorizer-b",
				"step",
				5*time.Second,
			),
			request1: newRequest(
				http.MethodGet,
				"https://example.com/authorize",
				nil,
			),
			request2: newRequest(
				http.MethodGet,
				"https://example.com/authorize",
				nil,
			),
		},
		"different ttl": {
			authorizer1: newAuthorizer(
				"authorizer",
				"authorizer",
				5*time.Second,
			),
			authorizer2: newAuthorizer(
				"authorizer",
				"authorizer",
				10*time.Second,
			),
			request1: newRequest(
				http.MethodGet,
				"https://example.com/authorize",
				nil,
			),
			request2: newRequest(
				http.MethodGet,
				"https://example.com/authorize",
				nil,
			),
		},
		"different request method": {
			authorizer1: newAuthorizer(
				"authorizer",
				"authorizer",
				5*time.Second,
			),
			authorizer2: newAuthorizer(
				"authorizer",
				"authorizer",
				5*time.Second,
			),
			request1: newRequest(
				http.MethodGet,
				"https://example.com/authorize",
				nil,
			),
			request2: newRequest(
				http.MethodPost,
				"https://example.com/authorize",
				nil,
			),
		},
		"different rendered url": {
			authorizer1: newAuthorizer(
				"authorizer",
				"authorizer",
				5*time.Second,
			),
			authorizer2: newAuthorizer(
				"authorizer",
				"authorizer",
				5*time.Second,
			),
			request1: newRequest(
				http.MethodGet,
				"https://example.com/tenant-a",
				nil,
			),
			request2: newRequest(
				http.MethodGet,
				"https://example.com/tenant-b",
				nil,
			),
		},
		"different header value": {
			authorizer1: newAuthorizer(
				"authorizer",
				"authorizer",
				5*time.Second,
			),
			authorizer2: newAuthorizer(
				"authorizer",
				"authorizer",
				5*time.Second,
			),
			request1: newRequest(
				http.MethodGet,
				"https://example.com/authorize",
				map[string]string{
					"X-Tenant-ID": "tenant-a",
				},
			),
			request2: newRequest(
				http.MethodGet,
				"https://example.com/authorize",
				map[string]string{
					"X-Tenant-ID": "tenant-b",
				},
			),
		},
		"different header name": {
			authorizer1: newAuthorizer(
				"authorizer",
				"authorizer",
				5*time.Second,
			),
			authorizer2: newAuthorizer(
				"authorizer",
				"authorizer",
				5*time.Second,
			),
			request1: newRequest(
				http.MethodGet,
				"https://example.com/authorize",
				map[string]string{
					"X-Tenant-ID": "foo",
				},
			),
			request2: newRequest(
				http.MethodGet,
				"https://example.com/authorize",
				map[string]string{
					"X-Organization-ID": "foo",
				},
			),
		},
		"different payload": {
			authorizer1: newAuthorizer(
				"authorizer",
				"authorizer",
				5*time.Second,
			),
			authorizer2: newAuthorizer(
				"authorizer",
				"authorizer",
				5*time.Second,
			),
			request1: newRequest(
				http.MethodPost,
				"https://example.com/authorize",
				nil,
			),
			request2: newRequest(
				http.MethodPost,
				"https://example.com/authorize",
				nil,
			),
			payload1: `{"tenant":"tenant-a"}`,
			payload2: `{"tenant":"tenant-b"}`,
		},
		"different authentication strategy": {
			authorizer1: &remoteAuthorizer{
				name: "authorizer",
				id:   "authorizer",
				ttl:  5 * time.Second,
				e: endpoint.Endpoint{
					AuthStrategy: authStrategyA,
				},
			},
			authorizer2: &remoteAuthorizer{
				name: "authorizer",
				id:   "authorizer",
				ttl:  5 * time.Second,
				e: endpoint.Endpoint{
					AuthStrategy: authStrategyB,
				},
			},
			request1: newRequest(
				http.MethodGet,
				"https://example.com/authorize",
				nil,
			),
			request2: newRequest(
				http.MethodGet,
				"https://example.com/authorize",
				nil,
			),
		},
		"same effective request despite different endpoint configuration": {
			authorizer1: &remoteAuthorizer{
				name: "authorizer",
				id:   "authorizer",
				ttl:  5 * time.Second,
				e: endpointtestsupport.EndpointValue(
					t,
					"https://example.com/{{ .Values.path }}",
				),
			},
			authorizer2: &remoteAuthorizer{
				name: "authorizer",
				id:   "authorizer",
				ttl:  5 * time.Second,
				e: endpointtestsupport.EndpointValue(
					t,
					"https://example.com/authorize",
				),
			},
			request1: newRequest(
				http.MethodGet,
				"https://example.com/authorize",
				nil,
			),
			request2: newRequest(
				http.MethodGet,
				"https://example.com/authorize",
				nil,
			),
			expectEqual: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			key1 := tc.authorizer1.calculateCacheKey(
				tc.request1,
				tc.payload1,
			)
			key2 := tc.authorizer2.calculateCacheKey(
				tc.request2,
				tc.payload2,
			)

			// THEN
			if tc.expectEqual {
				assert.Equal(t, key1, key2)
			} else {
				assert.NotEqual(t, key1, key2)
			}
		})
	}
}

func TestRemoteAuthorizerAccept(t *testing.T) {
	t.Parallel()

	mech := &remoteAuthorizer{}

	mech.Accept(nil)
}
