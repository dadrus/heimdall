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

package contextualizers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/heimdall"
	heimdallmocks "github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/values"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCreateGenericContextualizer(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		id     string
		config []byte
		assert func(t *testing.T, err error, contextualizer *genericContextualizer)
	}{
		{
			uc: "with unsupported fields",
			config: []byte(`
endpoint:
  url: http://foo.bar
foo: bar
`),
			assert: func(t *testing.T, err error, _ *genericContextualizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		{
			uc: "with invalid endpoint configuration",
			config: []byte(`
endpoint:
  method: POST
payload: bar
`),
			assert: func(t *testing.T, err error, _ *genericContextualizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'endpoint'.'url' is a required field")
			},
		},
		{
			uc: "with default cache",
			id: "contextualizer",
			config: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			assert: func(t *testing.T, err error, contextualizer *genericContextualizer) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, contextualizer)

				assert.Equal(t, "http://foo.bar", contextualizer.e.URL)
				require.NotNil(t, contextualizer.payload)
				val, err := contextualizer.payload.Render(map[string]any{
					"Subject": &subject.Subject{ID: "baz"},
				})
				require.NoError(t, err)
				assert.Equal(t, "bar", val)
				assert.Empty(t, contextualizer.fwdCookies)
				assert.Empty(t, contextualizer.fwdHeaders)
				assert.Equal(t, defaultTTL, contextualizer.ttl)
				assert.False(t, contextualizer.ContinueOnError())

				assert.Equal(t, "contextualizer", contextualizer.ID())
				assert.False(t, contextualizer.ContinueOnError())
			},
		},
		{
			uc: "with all fields configured",
			id: "contextualizer",
			config: []byte(`
endpoint:
  url: http://bar.foo
forward_headers:
  - X-User-ID
  - X-Foo-Bar
forward_cookies:
  - My-Foo-Session
payload: "{{ .Subject.ID }}"
cache_ttl: 5s
values:
  foo: "{{ .Subject.ID }}"
continue_pipeline_on_error: true
`),
			assert: func(t *testing.T, err error, contextualizer *genericContextualizer) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, contextualizer)

				assert.Equal(t, "http://bar.foo", contextualizer.e.URL)
				require.NotNil(t, contextualizer.payload)
				val, err := contextualizer.payload.Render(map[string]any{
					"Subject": &subject.Subject{ID: "baz"},
				})
				require.NoError(t, err)
				assert.Equal(t, "baz", val)
				assert.Len(t, contextualizer.fwdCookies, 1)
				assert.Contains(t, contextualizer.fwdCookies, "My-Foo-Session")
				assert.Len(t, contextualizer.fwdHeaders, 2)
				assert.Contains(t, contextualizer.fwdHeaders, "X-User-ID")
				assert.Contains(t, contextualizer.fwdHeaders, "X-Foo-Bar")
				assert.Equal(t, 5*time.Second, contextualizer.ttl)

				res, err := contextualizer.v.Render(map[string]any{
					"Subject": &subject.Subject{ID: "bar"},
				})
				require.NoError(t, err)
				assert.Equal(t, map[string]string{"foo": "bar"}, res)

				assert.Equal(t, "contextualizer", contextualizer.ID())
				assert.True(t, contextualizer.ContinueOnError())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			contextualizer, err := newGenericContextualizer(tc.id, conf)

			// THEN
			tc.assert(t, err, contextualizer)
		})
	}
}

func TestCreateGenericContextualizerFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		id              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *genericContextualizer, configured *genericContextualizer)
	}{
		{
			uc: "with empty config",
			id: "contextualizer1",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			assert: func(t *testing.T, err error, prototype *genericContextualizer, configured *genericContextualizer) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
				assert.Equal(t, "contextualizer1", configured.ID())
			},
		},
		{
			uc: "with unsupported fields",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			config: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, _ *genericContextualizer, _ *genericContextualizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		{
			uc: "with only payload reconfigured",
			id: "contextualizer2",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
forward_headers:
  - X-User-ID
  - X-Foo-Bar
forward_cookies:
  - My-Foo-Session
cache_ttl: 5s
`),
			config: []byte(`
payload: foo
`),
			assert: func(t *testing.T, err error, prototype *genericContextualizer, configured *genericContextualizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.id, configured.id)
				assert.NotEqual(t, prototype.payload, configured.payload)
				require.NotNil(t, configured.payload)
				val, err := configured.payload.Render(map[string]any{
					"Subject": &subject.Subject{ID: "baz"},
				})
				require.NoError(t, err)
				assert.Equal(t, "foo", val)
				assert.Equal(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Equal(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, "contextualizer2", configured.ID())
				assert.False(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
			},
		},
		{
			uc: "with payload and forward_headers reconfigured",
			id: "contextualizer3",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
forward_headers:
  - X-User-ID
  - X-Foo-Bar
forward_cookies:
  - My-Foo-Session
cache_ttl: 5s
`),
			config: []byte(`
payload: foo
forward_headers:
  - Foo-Bar
`),
			assert: func(t *testing.T, err error, prototype *genericContextualizer, configured *genericContextualizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.id, configured.id)
				assert.NotEqual(t, prototype.payload, configured.payload)
				require.NotNil(t, configured.payload)
				val, err := configured.payload.Render(map[string]any{
					"Subject": &subject.Subject{ID: "baz"},
				})
				require.NoError(t, err)
				assert.Equal(t, "foo", val)
				assert.NotEqual(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Len(t, configured.fwdHeaders, 1)
				assert.Contains(t, configured.fwdHeaders, "Foo-Bar")
				assert.Equal(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, "contextualizer3", configured.ID())
				assert.False(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
			},
		},
		{
			uc: "with payload, forward_headers and forward_cookies reconfigured",
			id: "contextualizer4",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
forward_headers:
  - X-User-ID
  - X-Foo-Bar
forward_cookies:
  - My-Foo-Session
cache_ttl: 5s
continue_pipeline_on_error: true
`),
			config: []byte(`
payload: foo
forward_headers:
  - Foo-Bar
forward_cookies:
  - Foo-Session
`),
			assert: func(t *testing.T, err error, prototype *genericContextualizer, configured *genericContextualizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.id, configured.id)
				assert.NotEqual(t, prototype.payload, configured.payload)
				require.NotNil(t, configured.payload)
				val, err := configured.payload.Render(map[string]any{
					"Subject": &subject.Subject{ID: "baz"},
				})
				require.NoError(t, err)
				assert.Equal(t, "foo", val)
				assert.NotEqual(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Len(t, configured.fwdHeaders, 1)
				assert.Contains(t, configured.fwdHeaders, "Foo-Bar")
				assert.NotEqual(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Len(t, configured.fwdCookies, 1)
				assert.Contains(t, configured.fwdCookies, "Foo-Session")
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, "contextualizer4", configured.ID())
				assert.True(t, prototype.ContinueOnError())
				assert.True(t, configured.ContinueOnError())
			},
		},
		{
			uc: "with everything possible, but values reconfigured",
			id: "contextualizer5",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
forward_headers:
  - X-User-ID
  - X-Foo-Bar
forward_cookies:
  - My-Foo-Session
cache_ttl: 5s
values:
  foo: bar
continue_pipeline_on_error: true
`),
			config: []byte(`
payload: foo
forward_headers:
  - Foo-Bar
forward_cookies:
  - Foo-Session
cache_ttl: 15s
continue_pipeline_on_error: false
`),
			assert: func(t *testing.T, err error, prototype *genericContextualizer, configured *genericContextualizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.id, configured.id)
				assert.NotEqual(t, prototype.payload, configured.payload)
				require.NotNil(t, configured.payload)
				val, err := configured.payload.Render(map[string]any{
					"Subject": &subject.Subject{ID: "baz"},
				})
				require.NoError(t, err)
				assert.Equal(t, "foo", val)
				assert.NotEqual(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Len(t, configured.fwdHeaders, 1)
				assert.Contains(t, configured.fwdHeaders, "Foo-Bar")
				assert.NotEqual(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Len(t, configured.fwdCookies, 1)
				assert.Contains(t, configured.fwdCookies, "Foo-Session")
				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, 15*time.Second, configured.ttl)
				assert.Equal(t, prototype.v, configured.v)
				assert.Equal(t, "contextualizer5", configured.ID())
				assert.True(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
			},
		},
		{
			uc: "with everything possible reconfigured",
			id: "contextualizer5",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
forward_headers:
  - X-User-ID
  - X-Foo-Bar
forward_cookies:
  - My-Foo-Session
cache_ttl: 5s
values:
  foo: bar
continue_pipeline_on_error: true
`),
			config: []byte(`
payload: foo
forward_headers:
  - Foo-Bar
forward_cookies:
  - Foo-Session
cache_ttl: 15s
values:
  bar: foo
continue_pipeline_on_error: false
`),
			assert: func(t *testing.T, err error, prototype *genericContextualizer, configured *genericContextualizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.NotEqual(t, prototype.v, configured.v)
				res, err := configured.v.Render(map[string]any{})
				require.NoError(t, err)
				assert.Equal(t, map[string]string{"bar": "foo", "foo": "bar"}, res)
				assert.Equal(t, prototype.id, configured.id)
				assert.NotEqual(t, prototype.payload, configured.payload)
				require.NotNil(t, configured.payload)
				val, err := configured.payload.Render(map[string]any{
					"Subject": &subject.Subject{ID: "baz"},
				})
				require.NoError(t, err)
				assert.Equal(t, "foo", val)
				assert.NotEqual(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Len(t, configured.fwdHeaders, 1)
				assert.Contains(t, configured.fwdHeaders, "Foo-Bar")
				assert.NotEqual(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Len(t, configured.fwdCookies, 1)
				assert.Contains(t, configured.fwdCookies, "Foo-Session")
				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, 15*time.Second, configured.ttl)
				assert.Equal(t, "contextualizer5", configured.ID())
				assert.True(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newGenericContextualizer(tc.id, pc)
			require.NoError(t, err)

			// WHEN
			concrete, err := prototype.WithConfig(conf)

			// THEN
			var (
				locContextualizer *genericContextualizer
				ok                bool
			)

			if err == nil {
				locContextualizer, ok = concrete.(*genericContextualizer)
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, locContextualizer)
		})
	}
}

func TestGenericContextualizerExecute(t *testing.T) {
	t.Parallel()

	var (
		remoteEndpointCalled bool
		checkRequest         func(req *http.Request)

		responseContentType string
		responseContent     []byte
		responseCode        int
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteEndpointCalled = true

		checkRequest(r)

		if responseContent != nil {
			w.Header().Set("Content-Type", responseContentType)
			w.Header().Set("Content-Length", strconv.Itoa(len(responseContent)))
			_, err := w.Write(responseContent)
			require.NoError(t, err)
		}

		w.WriteHeader(responseCode)
	}))
	defer srv.Close()

	for _, tc := range []struct {
		uc               string
		contextualizer   *genericContextualizer
		subject          *subject.Subject
		instructServer   func(t *testing.T)
		configureContext func(t *testing.T, ctx *heimdallmocks.ContextMock)
		configureCache   func(t *testing.T, cch *mocks.CacheMock, contextualizer *genericContextualizer,
			sub *subject.Subject)
		assert func(t *testing.T, err error, sub *subject.Subject, outputs map[string]any)
	}{
		{
			uc:             "fails due to nil subject",
			contextualizer: &genericContextualizer{id: "contextualizer", e: endpoint.Endpoint{URL: srv.URL}},
			assert: func(t *testing.T, err error, _ *subject.Subject, _ map[string]any) {
				t.Helper()

				assert.False(t, remoteEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "'nil' subject")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "contextualizer", identifier.ID())
			},
		},
		{
			uc: "with successful cache hit",
			contextualizer: &genericContextualizer{
				id:  "contextualizer",
				e:   endpoint.Endpoint{URL: srv.URL},
				ttl: 5 * time.Second,
				payload: func() template.Template {
					tpl, _ := template.New("foo")

					return tpl
				}(),
			},
			subject: &subject.Subject{ID: "Foo", Attributes: map[string]any{"bar": "baz"}},
			configureContext: func(t *testing.T, ctx *heimdallmocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			configureCache: func(t *testing.T, cch *mocks.CacheMock, _ *genericContextualizer,
				_ *subject.Subject,
			) {
				t.Helper()

				rawData, err := json.Marshal(&contextualizerData{Payload: "Hi Foo"})
				require.NoError(t, err)

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(rawData, nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject, outputs map[string]any) {
				t.Helper()

				assert.False(t, remoteEndpointCalled)

				require.NoError(t, err)
				assert.Len(t, sub.Attributes, 1)
				assert.Equal(t, "baz", sub.Attributes["bar"])

				assert.Len(t, outputs, 2)
				assert.Equal(t, "Hi Foo", outputs["contextualizer"])
				assert.Equal(t, "bar", outputs["foo"])
			},
		},
		{
			uc: "with error in values rendering",
			contextualizer: &genericContextualizer{
				id: "contextualizer1",
				e:  endpoint.Endpoint{URL: srv.URL},
				v: func() values.Values {
					tpl, err := template.New("{{ len .foo }}")
					require.NoError(t, err)

					return values.Values{"foo": tpl}
				}(),
			},
			subject: &subject.Subject{ID: "Foo", Attributes: map[string]any{"bar": "baz"}},
			configureContext: func(t *testing.T, ctx *heimdallmocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error, _ *subject.Subject, _ map[string]any) {
				t.Helper()

				assert.False(t, remoteEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to render values")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "contextualizer1", identifier.ID())
			},
		},
		{
			uc: "with error in payload rendering",
			contextualizer: &genericContextualizer{
				id: "contextualizer1",
				e:  endpoint.Endpoint{URL: srv.URL},
				payload: func() template.Template {
					tpl, err := template.New("{{ len .foo }}")
					require.NoError(t, err)

					return tpl
				}(),
			},
			subject: &subject.Subject{ID: "Foo", Attributes: map[string]any{"bar": "baz"}},
			configureContext: func(t *testing.T, ctx *heimdallmocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error, _ *subject.Subject, _ map[string]any) {
				t.Helper()

				assert.False(t, remoteEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to render payload")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "contextualizer1", identifier.ID())
			},
		},
		{
			uc: "with communication error (dns)",
			contextualizer: &genericContextualizer{
				id: "contextualizer2",
				e:  endpoint.Endpoint{URL: "http://heimdall.test.local"},
			},
			subject: &subject.Subject{ID: "Foo", Attributes: map[string]any{"bar": "baz"}},
			configureContext: func(t *testing.T, ctx *heimdallmocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error, _ *subject.Subject, _ map[string]any) {
				t.Helper()

				assert.False(t, remoteEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "contextualizer endpoint failed")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "contextualizer2", identifier.ID())
			},
		},
		{
			uc: "with unexpected response code from server",
			contextualizer: &genericContextualizer{
				id: "contextualizer3",
				e:  endpoint.Endpoint{URL: srv.URL},
			},
			subject: &subject.Subject{ID: "Foo", Attributes: map[string]any{"bar": "baz"}},
			instructServer: func(t *testing.T) {
				t.Helper()

				responseCode = http.StatusInternalServerError
			},
			configureContext: func(t *testing.T, ctx *heimdallmocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error, _ *subject.Subject, _ map[string]any) {
				t.Helper()

				assert.True(t, remoteEndpointCalled)

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "unexpected response code")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "contextualizer3", identifier.ID())
			},
		},
		{
			uc: "without payload, but values, without cache hit",
			contextualizer: &genericContextualizer{
				id:  "test-contextualizer",
				ttl: 5 * time.Second,
				e:   endpoint.Endpoint{URL: srv.URL + "/{{ .Values.user_id }}"},
				v: func() values.Values {
					tpl, err := template.New("{{ .Subject.ID }}")
					require.NoError(t, err)

					return values.Values{"user_id": tpl}
				}(),
			},
			subject: &subject.Subject{ID: "Foo", Attributes: map[string]any{"bar": "baz"}},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "/Foo", req.URL.Path)
				}

				responseCode = http.StatusAccepted
			},
			configureContext: func(t *testing.T, ctx *heimdallmocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			configureCache: func(t *testing.T, cch *mocks.CacheMock, _ *genericContextualizer,
				_ *subject.Subject,
			) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject, outputs map[string]any) {
				t.Helper()

				assert.True(t, remoteEndpointCalled)

				require.NoError(t, err)

				assert.Len(t, sub.Attributes, 1)
				assert.Len(t, outputs, 1)
			},
		},
		{
			uc: "without payload, but with cache",
			contextualizer: &genericContextualizer{
				id:  "test-contextualizer",
				e:   endpoint.Endpoint{URL: srv.URL + "/{{ .Subject.ID }}"},
				ttl: 10 * time.Second,
			},
			subject: &subject.Subject{ID: "Foo", Attributes: map[string]any{"bar": "baz"}},
			configureCache: func(t *testing.T, cch *mocks.CacheMock, contextualizer *genericContextualizer,
				_ *subject.Subject,
			) {
				t.Helper()

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.MatchedBy(func(data []byte) bool {
					var val contextualizerData
					err := json.Unmarshal(data, &val)

					return err == nil && val.Payload == "Hi from endpoint"
				}), contextualizer.ttl).Return(nil)
			},
			configureContext: func(t *testing.T, ctx *heimdallmocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "/Foo", req.URL.Path)
				}

				responseContentType = "text/text"
				responseContent = []byte(`Hi from endpoint`)
				responseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, sub *subject.Subject, outputs map[string]any) {
				t.Helper()

				assert.True(t, remoteEndpointCalled)

				require.NoError(t, err)

				assert.Len(t, sub.Attributes, 1)
				assert.Len(t, outputs, 2)
				assert.Equal(t, "Hi from endpoint", outputs["test-contextualizer"])
			},
		},
		{
			uc: "with rendered payload and headers, as well as forwarded headers and cookies",
			contextualizer: &genericContextualizer{
				id: "test-contextualizer",
				e: endpoint.Endpoint{
					URL: srv.URL + "/{{ .Subject.ID }}/{{ .Outputs.foo }}",
					Headers: map[string]string{
						"Content-Type": "application/json",
						"Accept":       "application/json",
						"X-Bar":        "{{ .Subject.Attributes.bar }}",
						"X-Foo":        "{{ .Outputs.foo }}",
					},
				},
				v: func() values.Values {
					tpl, _ := template.New("bar")

					return values.Values{"foo": tpl}
				}(),
				payload: func() template.Template {
					tpl, _ := template.New(`
{
	"user_id": {{ quote .Subject.ID }},
	"value": {{ quote .Values.foo }},
    "foo": {{ quote .Outputs.foo }}
}
`)

					return tpl
				}(),
				fwdHeaders: []string{"X-Bar-Foo"},
				fwdCookies: []string{"X-Foo-Session"},
			},
			subject: &subject.Subject{ID: "Foo", Attributes: map[string]any{"bar": "baz"}},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "/Foo/bar", req.URL.Path)
					assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, "baz", req.Header.Get("X-Bar"))
					assert.Equal(t, "bar", req.Header.Get("X-Foo"))
					assert.Equal(t, "Hi Foo", req.Header.Get("X-Bar-Foo"))
					cookie, err := req.Cookie("X-Foo-Session")
					require.NoError(t, err)
					assert.Equal(t, "Foo-Session-Value", cookie.Value)

					content, err := io.ReadAll(req.Body)
					require.NoError(t, err)

					assert.JSONEq(t, `{"user_id": "Foo", "value": "bar", "foo":"bar"}`, string(content))
				}

				responseContentType = "application/json"
				responseContent = []byte(`{ "baz": "foo" }`)
				responseCode = http.StatusOK
			},
			configureContext: func(t *testing.T, ctx *heimdallmocks.ContextMock) {
				t.Helper()

				reqf := heimdallmocks.NewRequestFunctionsMock(t)
				reqf.EXPECT().Header("X-Bar-Foo").Return("Hi Foo")
				reqf.EXPECT().Cookie("X-Foo-Session").Return("Foo-Session-Value")

				ctx.EXPECT().Request().Return(
					&heimdall.Request{
						RequestFunctions: reqf,
						Method:           http.MethodPost,
						URL:              &heimdall.URL{URL: url.URL{Scheme: "http", Host: "foobar.baz", Path: "zab"}},
					})
			},
			assert: func(t *testing.T, err error, sub *subject.Subject, outputs map[string]any) {
				t.Helper()

				assert.True(t, remoteEndpointCalled)

				require.NoError(t, err)

				assert.Len(t, sub.Attributes, 1)

				assert.Len(t, outputs, 2)
				entry := outputs["test-contextualizer"]
				assert.Len(t, entry, 1)
				assert.Contains(t, entry, "baz")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			remoteEndpointCalled = false
			responseContentType = ""
			responseContent = nil

			checkRequest = func(*http.Request) { t.Helper() }

			instructServer := x.IfThenElse(tc.instructServer != nil,
				tc.instructServer,
				func(t *testing.T) { t.Helper() })

			configureContext := x.IfThenElse(tc.configureContext != nil,
				tc.configureContext,
				func(t *testing.T, _ *heimdallmocks.ContextMock) { t.Helper() })

			configureCache := x.IfThenElse(tc.configureCache != nil,
				tc.configureCache,
				func(t *testing.T, _ *mocks.CacheMock, _ *genericContextualizer, _ *subject.Subject) {
					t.Helper()
				})

			cch := mocks.NewCacheMock(t)

			ctx := heimdallmocks.NewContextMock(t)
			ctx.EXPECT().AppContext().Return(cache.WithContext(context.Background(), cch))
			ctx.EXPECT().Outputs().Return(map[string]any{"foo": "bar"})

			configureContext(t, ctx)
			configureCache(t, cch, tc.contextualizer, tc.subject)
			instructServer(t)

			// WHEN
			err := tc.contextualizer.Execute(ctx, tc.subject)

			// THEN
			tc.assert(t, err, tc.subject, ctx.Outputs())
		})
	}
}
