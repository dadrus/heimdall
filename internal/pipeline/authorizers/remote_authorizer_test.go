package authorizers

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/pipeline/template"
	"github.com/dadrus/heimdall/internal/pipeline/testsupport"
	"github.com/dadrus/heimdall/internal/x"
)

func TestCreateRemoteAuthorizer(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, auth *remoteAuthorizer)
	}{
		{
			uc: "configuration with unknown properties",
			config: []byte(`
endpoint:
  url: http://foo.bar
foo: bar
`),
			assert: func(t *testing.T, err error, auth *remoteAuthorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
		{
			uc: "configuration with invalid endpoint config",
			config: []byte(`
endpoint:
  method: FOO
payload: FooBar
`),
			assert: func(t *testing.T, err error, auth *remoteAuthorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to validate endpoint")
			},
		},
		{
			uc: "configuration without both payload and header",
			config: []byte(`
endpoint:
  url: http://foo.bar
`),
			assert: func(t *testing.T, err error, auth *remoteAuthorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "either a payload or at least")
			},
		},
		{
			uc: "configuration with endpoint and payload",
			config: []byte(`
endpoint:
  url: http://foo.bar
payload: "{{ .ID }}"
`),
			assert: func(t *testing.T, err error, auth *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, auth)
				assert.Equal(t, template.Template("{{ .ID }}"), auth.payload)
				assert.Empty(t, auth.headerForUpstream)
				assert.Zero(t, auth.ttl)
			},
		},
		{
			uc: "full configuration",
			config: []byte(`
endpoint:
  url: http://foo.bar
payload: "{{ .Attributes.foo }}"
forward_response_header_to_upstream:
  - Foo
  - Bar
cache_ttl: 5s
`),
			assert: func(t *testing.T, err error, auth *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, auth)
				assert.Equal(t, template.Template("{{ .Attributes.foo }}"), auth.payload)
				assert.Len(t, auth.headerForUpstream, 2)
				assert.Contains(t, auth.headerForUpstream, "Foo")
				assert.Contains(t, auth.headerForUpstream, "Bar")
				assert.NotNil(t, auth.ttl)
				assert.Equal(t, 5*time.Second, auth.ttl)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			auth, err := newRemoteAuthorizer(tc.uc, conf)

			// THEN
			if err == nil {
				assert.Equal(t, tc.uc, auth.name)
			}

			tc.assert(t, err, auth)
		})
	}
}

func TestCreateRemoteAuthorizerFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *remoteAuthorizer, configured *remoteAuthorizer)
	}{
		{
			uc: "without new configuration",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			assert: func(t *testing.T, err error, prototype *remoteAuthorizer, configured *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc: "with empty configuration",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			config: []byte(``),
			assert: func(t *testing.T, err error, prototype *remoteAuthorizer, configured *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc: "configuration with unknown properties",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			config: []byte(`
foo: bar
`),
			assert: func(t *testing.T, err error, prototype *remoteAuthorizer, configured *remoteAuthorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
		{
			uc: "with overwritten empty payload",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			config: []byte(`
payload: ""
cache_ttl: 1s
`),
			assert: func(t *testing.T, err error, prototype *remoteAuthorizer, configured *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.NotNil(t, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.name, configured.name)
				assert.Equal(t, prototype.payload, configured.payload)
				assert.Empty(t, configured.headerForUpstream)
				assert.NotNil(t, configured.ttl)
			},
		},
		{
			uc: "with everything possible reconfigured",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
  headers:
    Foo: Bar
`),
			config: []byte(`
payload: Baz
forward_response_header_to_upstream:
  - Bar
  - Foo
cache_ttl: 15s
`),
			assert: func(t *testing.T, err error, prototype *remoteAuthorizer, configured *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.NotNil(t, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.name, configured.name)
				assert.Equal(t, template.Template("Baz"), configured.payload)
				assert.Len(t, configured.headerForUpstream, 2)
				assert.Contains(t, configured.headerForUpstream, "Bar")
				assert.Contains(t, configured.headerForUpstream, "Foo")
				assert.Equal(t, 15*time.Second, configured.ttl)

				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.NotEqual(t, prototype.headerForUpstream, configured.headerForUpstream)
				assert.NotEqual(t, prototype.payload, configured.payload)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newRemoteAuthorizer(tc.uc, pc)
			require.NoError(t, err)

			// WHEN
			auth, err := prototype.WithConfig(conf)

			// THEN
			var (
				locAuth *remoteAuthorizer
				ok      bool
			)

			if err == nil {
				locAuth, ok = auth.(*remoteAuthorizer)
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, locAuth)
		})
	}
}

// nolint: maintidx
func TestRemoteAuthorizerExecute(t *testing.T) {
	t.Parallel()

	var (
		authorizationEndpointCalled bool
		checkRequest                func(req *http.Request)

		responseHeader      map[string]string
		responseContentType string
		responseContent     []byte
		responseCode        int
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizationEndpointCalled = true

		checkRequest(r)

		for hn, hv := range responseHeader {
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
		uc               string
		authorizer       *remoteAuthorizer
		subject          *subject.Subject
		instructServer   func(t *testing.T)
		configureContext func(t *testing.T, ctx *testsupport.MockContext)
		configureCache   func(t *testing.T, cch *testsupport.MockCache, authorizer *remoteAuthorizer, sub *subject.Subject)
		assert           func(t *testing.T, err error, sub *subject.Subject)
	}{
		{
			// nolint: lll
			uc: "successful with payload and with header, without payload from server and without header forwarding and with disabled cache",
			authorizer: &remoteAuthorizer{
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"Foo-Bar": "{{ .Attributes.bar }}"},
				},
				payload: "{{ .ID }}",
			},
			subject: &subject.Subject{
				ID:         "my-id",
				Attributes: map[string]any{"bar": "baz"},
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				responseCode = http.StatusOK

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "POST", req.Method)
					assert.Equal(t, "baz", req.Header.Get("Foo-Bar"))
					assert.Empty(t, req.Header.Get("Content-Type"))
					assert.Empty(t, req.Header.Get("Accept"))

					data, err := ioutil.ReadAll(req.Body)
					assert.NoError(t, err)

					assert.Equal(t, "my-id", string(data))
				}
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.NoError(t, err)

				assert.True(t, authorizationEndpointCalled)
				assert.Len(t, sub.Attributes, 1)
				assert.Equal(t, "baz", sub.Attributes["bar"])
			},
		},
		{
			// nolint: lll
			uc: "successful with json payload and with header, with json payload from server and with header forwarding and with disabled cache",
			authorizer: &remoteAuthorizer{
				name: "authorizer",
				e: endpoint.Endpoint{
					URL: srv.URL,
					Headers: map[string]string{
						"Content-Type": "application/json",
						"Accept":       "application/json",
						"Foo-Bar":      "{{ .Attributes.bar }}",
					},
				},
				payload:           `{ "user_id": {{ quote .ID }} }`,
				headerForUpstream: []string{"X-Foo-Bar", "X-Bar-Foo"},
			},
			subject: &subject.Subject{
				ID:         "my-id",
				Attributes: map[string]any{"bar": "baz"},
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "POST", req.Method)
					assert.Equal(t, "baz", req.Header.Get("Foo-Bar"))
					assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))

					data, err := ioutil.ReadAll(req.Body)
					assert.NoError(t, err)

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
				responseHeader = map[string]string{"X-Foo-Bar": "HeyFoo"}
			},
			configureContext: func(t *testing.T, ctx *testsupport.MockContext) {
				t.Helper()

				ctx.On("AddResponseHeader", "X-Foo-Bar", "HeyFoo")
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.NoError(t, err)

				assert.True(t, authorizationEndpointCalled)
				assert.Len(t, sub.Attributes, 2)
				assert.Equal(t, "baz", sub.Attributes["bar"])

				attrs := sub.Attributes["authorizer"]
				assert.NotEmpty(t, attrs)
				authorizerAttrs, ok := attrs.(map[string]any)
				require.True(t, ok)
				assert.Len(t, authorizerAttrs, 3)
				assert.Equal(t, true, authorizerAttrs["access_granted"])
				assert.Len(t, authorizerAttrs["permissions"], 2)
				assert.Contains(t, authorizerAttrs["permissions"], "read_foo")
				assert.Contains(t, authorizerAttrs["permissions"], "write_foo")
				assert.Len(t, authorizerAttrs["groups"], 1)
				assert.Contains(t, authorizerAttrs["groups"], "Foo-Users")
			},
		},
		{
			// nolint: lll
			uc: "successful with www-form-urlencoded payload and without header, without payload from server and with header forwarding and with failing cache hit",
			authorizer: &remoteAuthorizer{
				name: "authorizer",
				e: endpoint.Endpoint{
					URL: srv.URL,
					Headers: map[string]string{
						"Content-Type": "application/x-www-form-urlencoded",
					},
				},
				payload:           `user_id={{ urlenc .ID }}&{{ .Attributes.bar }}=foo`,
				headerForUpstream: []string{"X-Foo-Bar", "X-Bar-Foo"},
				ttl:               20 * time.Second,
			},
			subject: &subject.Subject{
				ID:         "my id",
				Attributes: map[string]any{"bar": "baz"},
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					t.Helper()

					assert.Equal(t, "POST", req.Method)
					assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))

					data, err := ioutil.ReadAll(req.Body)
					assert.NoError(t, err)

					formValues, err := url.ParseQuery(string(data))
					require.NoError(t, err)

					assert.Len(t, formValues, 2)
					assert.Equal(t, []string{"my id"}, formValues["user_id"])
					assert.Equal(t, []string{"foo"}, formValues["baz"])
				}

				responseCode = http.StatusOK
				responseHeader = map[string]string{"X-Foo-Bar": "HeyFoo"}
			},
			configureContext: func(t *testing.T, ctx *testsupport.MockContext) {
				t.Helper()

				ctx.On("AddResponseHeader", "X-Foo-Bar", "HeyFoo")
			},
			configureCache: func(t *testing.T, cch *testsupport.MockCache, auth *remoteAuthorizer, sub *subject.Subject) {
				t.Helper()

				cacheKey, err := auth.calculateCacheKey(sub)
				require.NoError(t, err)

				cch.On("Get", cacheKey).Return(nil)
				cch.On("Set", cacheKey,
					mock.MatchedBy(func(val *authorizationInformation) bool {
						return val != nil && val.payload == nil && len(val.header.Get("X-Foo-Bar")) != 0
					}), auth.ttl)
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.NoError(t, err)

				assert.True(t, authorizationEndpointCalled)
				assert.Len(t, sub.Attributes, 1)
				assert.Equal(t, "baz", sub.Attributes["bar"])

				assert.Empty(t, sub.Attributes["authorizer"])
			},
		},
		{
			uc: "successfully reuse cache",
			authorizer: &remoteAuthorizer{
				name: "authorizer",
				e: endpoint.Endpoint{
					URL: srv.URL,
					Headers: map[string]string{
						"Content-Type": "application/x-www-form-urlencoded",
						"Foo-Bar":      "{{ .Attributes.bar }}",
					},
				},
				payload:           `user_id={{ urlenc .ID }}&{{ .Attributes.bar }}=foo`,
				headerForUpstream: []string{"X-Foo-Bar", "X-Bar-Foo"},
				ttl:               20 * time.Second,
			},
			subject: &subject.Subject{
				ID:         "my id",
				Attributes: map[string]any{"bar": "baz"},
			},
			configureContext: func(t *testing.T, ctx *testsupport.MockContext) {
				t.Helper()

				ctx.On("AddResponseHeader", "X-Foo-Bar", "HeyFoo")
				ctx.On("AddResponseHeader", "X-Bar-Foo", "HeyBar")
			},
			configureCache: func(t *testing.T, cch *testsupport.MockCache, auth *remoteAuthorizer, sub *subject.Subject) {
				t.Helper()

				cacheKey, err := auth.calculateCacheKey(sub)
				require.NoError(t, err)

				cch.On("Get", cacheKey).Return(&authorizationInformation{
					header: http.Header{
						"X-Foo-Bar": {"HeyFoo"},
						"X-Bar-Foo": {"HeyBar"},
					},
					payload: map[string]string{"foo": "bar"},
				})
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.NoError(t, err)

				assert.False(t, authorizationEndpointCalled)
				assert.Len(t, sub.Attributes, 2)
				assert.Equal(t, "baz", sub.Attributes["bar"])

				attrs := sub.Attributes["authorizer"]
				assert.NotEmpty(t, attrs)
				authorizerAttrs, ok := attrs.(map[string]string)
				require.True(t, ok)
				assert.Len(t, authorizerAttrs, 1)
				assert.Equal(t, "bar", authorizerAttrs["foo"])
			},
		},
		{
			// nolint: godox
			// FIXME: This test fails from time to time
			uc: "cache with bad object in cache",
			authorizer: &remoteAuthorizer{
				name: "authorizer",
				e: endpoint.Endpoint{
					URL: srv.URL,
					Headers: map[string]string{
						"Content-Type": "application/x-www-form-urlencoded",
						"Foo-Bar":      "{{ .Attributes.bar }}",
					},
				},
				payload:           `user_id={{ urlenc .ID }}&{{ .Attributes.bar }}=foo`,
				headerForUpstream: []string{"X-Foo-Bar", "X-Bar-Foo"},
				ttl:               20 * time.Second,
			},
			subject: &subject.Subject{
				ID:         "my id",
				Attributes: map[string]any{"bar": "baz"},
			},
			configureContext: func(t *testing.T, ctx *testsupport.MockContext) {
				t.Helper()

				ctx.On("AddResponseHeader", "X-Foo-Bar", "HeyFoo")
			},
			configureCache: func(t *testing.T, cch *testsupport.MockCache, auth *remoteAuthorizer, sub *subject.Subject) {
				t.Helper()

				cacheKey, err := auth.calculateCacheKey(sub)
				require.NoError(t, err)

				cch.On("Get", mock.Anything).Return("Hello Foo")
				cch.On("Delete", cacheKey)
				cch.On("Set", cacheKey, mock.Anything, auth.ttl)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				responseCode = http.StatusOK
				responseHeader = map[string]string{"X-Foo-Bar": "HeyFoo"}

				rawData, err := json.Marshal(map[string]any{
					"access_granted": true,
				})
				require.NoError(t, err)
				responseContent = rawData
				responseContentType = "application/json"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.NoError(t, err)

				assert.True(t, authorizationEndpointCalled)
				assert.Len(t, sub.Attributes, 2)
				assert.Equal(t, "baz", sub.Attributes["bar"])

				assert.Len(t, sub.Attributes["authorizer"], 1)
			},
		},
		{
			uc: "with failed authorization",
			authorizer: &remoteAuthorizer{
				name: "authorizer",
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"X-User-ID": "{{ .ID }}"},
				},
			},
			subject: &subject.Subject{ID: "foo"},
			instructServer: func(t *testing.T) {
				t.Helper()

				checkRequest = func(req *http.Request) {
					assert.Equal(t, "foo", req.Header.Get("X-User-ID"))
				}

				responseCode = http.StatusUnauthorized
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.Error(t, err)

				assert.ErrorIs(t, err, heimdall.ErrAuthorization)
				assert.Contains(t, err.Error(), "authorization failed")
			},
		},
		{
			uc: "with unsupported response content type",
			authorizer: &remoteAuthorizer{
				name: "foo",
				e: endpoint.Endpoint{
					URL:     srv.URL,
					Headers: map[string]string{"X-User-ID": "{{ .ID }}"},
				},
			},
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{}},
			instructServer: func(t *testing.T) {
				t.Helper()

				responseContent = []byte("Hi Foo")
				responseContentType = "text/text"
				responseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.NoError(t, err)

				assert.True(t, authorizationEndpointCalled)
				assert.Equal(t, "Hi Foo", sub.Attributes["foo"])
			},
		},
		{
			uc: "with communication error (dns)",
			authorizer: &remoteAuthorizer{
				name:    "authorizer",
				e:       endpoint.Endpoint{URL: "http://heimdall.test.local"},
				payload: template.Template("bar"),
			},
			subject: &subject.Subject{ID: "foo"},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "endpoint failed")

				assert.False(t, authorizationEndpointCalled)
			},
		},
		{
			uc:         "with error due to nil subject",
			authorizer: &remoteAuthorizer{},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, authorizationEndpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "due to 'nil' subject")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			authorizationEndpointCalled = false
			responseHeader = nil
			responseContentType = ""
			responseContent = nil

			checkRequest = func(req *http.Request) { t.Helper() }

			instructServer := x.IfThenElse(tc.instructServer != nil,
				tc.instructServer,
				func(t *testing.T) { t.Helper() })

			configureContext := x.IfThenElse(tc.configureContext != nil,
				tc.configureContext,
				func(t *testing.T, ctx *testsupport.MockContext) { t.Helper() })

			configureCache := x.IfThenElse(tc.configureCache != nil,
				tc.configureCache,
				func(t *testing.T, ctx *testsupport.MockCache, auth *remoteAuthorizer, sub *subject.Subject) {
					t.Helper()
				})

			cch := &testsupport.MockCache{}

			ctx := &testsupport.MockContext{}
			ctx.On("AppContext").Return(cache.WithContext(context.Background(), cch))

			configureContext(t, ctx)
			configureCache(t, cch, tc.authorizer, tc.subject)
			instructServer(t)

			// WHEN
			err := tc.authorizer.Execute(ctx, tc.subject)

			// THEN
			tc.assert(t, err, tc.subject)

			ctx.AssertExpectations(t)
			cch.AssertExpectations(t)
		})
	}
}
