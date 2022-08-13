package hydrators

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/heimdall"
	heimdallmocks "github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/pipeline/template"
	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/dadrus/heimdall/internal/x"
)

func TestCreateGenericHydrator(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, hydrator *genericHydrator)
	}{
		{
			uc: "with unsupported fields",
			config: []byte(`
endpoint:
  url: http://foo.bar
foo: bar
`),
			assert: func(t *testing.T, err error, hydrator *genericHydrator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
		{
			uc: "with invalid endpoint configuration",
			config: []byte(`
endpoint:
  method: POST
payload: bar
`),
			assert: func(t *testing.T, err error, hydrator *genericHydrator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to validate endpoint")
			},
		},
		{
			uc: "with default cache",
			config: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			assert: func(t *testing.T, err error, hydrator *genericHydrator) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, hydrator)

				assert.Equal(t, "http://foo.bar", hydrator.e.URL)
				require.NotNil(t, hydrator.payload)
				val, err := hydrator.payload.Render(nil, &subject.Subject{ID: "baz"})
				require.NoError(t, err)
				assert.Equal(t, "bar", val)
				assert.Empty(t, hydrator.fwdCookies)
				assert.Empty(t, hydrator.fwdHeaders)
				assert.Equal(t, defaultTTL, hydrator.ttl)
			},
		},
		{
			uc: "with all fields configured",
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
`),
			assert: func(t *testing.T, err error, hydrator *genericHydrator) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, hydrator)

				assert.Equal(t, "http://bar.foo", hydrator.e.URL)
				require.NotNil(t, hydrator.payload)
				val, err := hydrator.payload.Render(nil, &subject.Subject{ID: "baz"})
				require.NoError(t, err)
				assert.Equal(t, "baz", val)
				assert.Len(t, hydrator.fwdCookies, 1)
				assert.Contains(t, hydrator.fwdCookies, "My-Foo-Session")
				assert.Len(t, hydrator.fwdHeaders, 2)
				assert.Contains(t, hydrator.fwdHeaders, "X-User-ID")
				assert.Contains(t, hydrator.fwdHeaders, "X-Foo-Bar")
				assert.Equal(t, 5*time.Second, hydrator.ttl)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			hydrator, err := newGenericHydrator(tc.uc, conf)

			// THEN
			if err == nil {
				assert.Equal(t, tc.uc, hydrator.name)
			}

			tc.assert(t, err, hydrator)
		})
	}
}

func TestCreateGenericHydratorFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *genericHydrator, configured *genericHydrator)
	}{
		{
			uc: "with empty config",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			assert: func(t *testing.T, err error, prototype *genericHydrator, configured *genericHydrator) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
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
			assert: func(t *testing.T, err error, prototype *genericHydrator, configured *genericHydrator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
		{
			uc: "with only payload reconfigured",
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
			assert: func(t *testing.T, err error, prototype *genericHydrator, configured *genericHydrator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.name, configured.name)
				assert.NotEqual(t, prototype.payload, configured.payload)
				require.NotNil(t, configured.payload)
				val, err := configured.payload.Render(nil, &subject.Subject{ID: "baz"})
				require.NoError(t, err)
				assert.Equal(t, "foo", val)
				assert.Equal(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Equal(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Equal(t, prototype.ttl, configured.ttl)
			},
		},
		{
			uc: "with payload and forward_headers reconfigured",
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
			assert: func(t *testing.T, err error, prototype *genericHydrator, configured *genericHydrator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.name, configured.name)
				assert.NotEqual(t, prototype.payload, configured.payload)
				require.NotNil(t, configured.payload)
				val, err := configured.payload.Render(nil, &subject.Subject{ID: "baz"})
				require.NoError(t, err)
				assert.Equal(t, "foo", val)
				assert.NotEqual(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Len(t, configured.fwdHeaders, 1)
				assert.Contains(t, configured.fwdHeaders, "Foo-Bar")
				assert.Equal(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Equal(t, prototype.ttl, configured.ttl)
			},
		},
		{
			uc: "with payload, forward_headers and forward_cookies reconfigured",
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
forward_cookies:
  - Foo-Session
`),
			assert: func(t *testing.T, err error, prototype *genericHydrator, configured *genericHydrator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.name, configured.name)
				assert.NotEqual(t, prototype.payload, configured.payload)
				require.NotNil(t, configured.payload)
				val, err := configured.payload.Render(nil, &subject.Subject{ID: "baz"})
				require.NoError(t, err)
				assert.Equal(t, "foo", val)
				assert.NotEqual(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Len(t, configured.fwdHeaders, 1)
				assert.Contains(t, configured.fwdHeaders, "Foo-Bar")
				assert.NotEqual(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Len(t, configured.fwdCookies, 1)
				assert.Contains(t, configured.fwdCookies, "Foo-Session")
				assert.Equal(t, prototype.ttl, configured.ttl)
			},
		},
		{
			uc: "with everything reconfigured",
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
forward_cookies:
  - Foo-Session
cache_ttl: 15s
`),
			assert: func(t *testing.T, err error, prototype *genericHydrator, configured *genericHydrator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.name, configured.name)
				assert.NotEqual(t, prototype.payload, configured.payload)
				require.NotNil(t, configured.payload)
				val, err := configured.payload.Render(nil, &subject.Subject{ID: "baz"})
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
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newGenericHydrator(tc.uc, pc)
			require.NoError(t, err)

			// WHEN
			auth, err := prototype.WithConfig(conf)

			// THEN
			var (
				locAuth *genericHydrator
				ok      bool
			)

			if err == nil {
				locAuth, ok = auth.(*genericHydrator)
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, locAuth)
		})
	}
}

// nolint: maintidx
func TestGenericHydratorExecute(t *testing.T) {
	t.Parallel()

	var (
		hydrationEndpointCalled bool
		checkRequest            func(req *http.Request)

		responseContentType string
		responseContent     []byte
		responseCode        int
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hydrationEndpointCalled = true

		checkRequest(r)

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
		hydrator         *genericHydrator
		subject          *subject.Subject
		instructServer   func(t *testing.T)
		configureContext func(t *testing.T, ctx *heimdallmocks.MockContext)
		configureCache   func(t *testing.T, cch *mocks.MockCache, hydrator *genericHydrator, sub *subject.Subject)
		assert           func(t *testing.T, err error, sub *subject.Subject)
	}{
		{
			uc:       "fails due to nil subject",
			hydrator: &genericHydrator{e: endpoint.Endpoint{URL: srv.URL}},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, hydrationEndpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "'nil' subject")
			},
		},
		{
			uc: "with successful cache hit",
			hydrator: &genericHydrator{
				name: "hydrator",
				e:    endpoint.Endpoint{URL: srv.URL},
				ttl:  5 * time.Second,
				payload: func() template.Template {
					tpl, _ := template.New("foo")

					return tpl
				}(),
			},
			subject: &subject.Subject{ID: "Foo", Attributes: map[string]any{"bar": "baz"}},
			configureCache: func(t *testing.T, cch *mocks.MockCache, hydrator *genericHydrator, sub *subject.Subject) {
				t.Helper()

				key, err := hydrator.calculateCacheKey(sub)
				require.NoError(t, err)

				cch.On("Get", key).Return(&hydrationData{payload: "Hi Foo"})
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, hydrationEndpointCalled)

				require.NoError(t, err)
				assert.Len(t, sub.Attributes, 2)
				assert.Equal(t, sub.Attributes["hydrator"], "Hi Foo")
			},
		},
		{
			uc: "with wrong object type in cache",
			hydrator: &genericHydrator{
				name: "hydrator",
				e:    endpoint.Endpoint{URL: srv.URL},
				ttl:  5 * time.Second,
				payload: func() template.Template {
					tpl, _ := template.New("foo")

					return tpl
				}(),
			},
			subject: &subject.Subject{ID: "Foo", Attributes: map[string]any{"bar": "baz"}},
			configureCache: func(t *testing.T, cch *mocks.MockCache, hydrator *genericHydrator, sub *subject.Subject) {
				t.Helper()

				key, err := hydrator.calculateCacheKey(sub)
				require.NoError(t, err)

				cch.On("Get", key).Return("Hi Foo")
				cch.On("Delete", key)
				cch.On("Set", key, mock.MatchedBy(func(val *hydrationData) bool {
					return val != nil && val.payload == "Hi from endpoint"
				}), 5*time.Second)
			},
			instructServer: func(t *testing.T) {
				t.Helper()

				responseContentType = "text/text"
				responseContent = []byte(`Hi from endpoint`)
				responseCode = http.StatusOK
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, hydrationEndpointCalled)

				require.NoError(t, err)
				assert.Len(t, sub.Attributes, 2)
				assert.Equal(t, sub.Attributes["hydrator"], "Hi from endpoint")
			},
		},
		{
			uc: "with error in payload rendering",
			hydrator: &genericHydrator{
				name: "hydrator",
				e:    endpoint.Endpoint{URL: srv.URL},
				payload: func() template.Template {
					tpl, _ := template.New("{{ .foo }}")

					return tpl
				}(),
			},
			subject: &subject.Subject{ID: "Foo", Attributes: map[string]any{"bar": "baz"}},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, hydrationEndpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to render payload")
			},
		},
		{
			uc: "with communication error (dns)",
			hydrator: &genericHydrator{
				name: "hydrator",
				e:    endpoint.Endpoint{URL: "http://heimdall.test.local"},
			},
			subject: &subject.Subject{ID: "Foo", Attributes: map[string]any{"bar": "baz"}},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, hydrationEndpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "hydration endpoint failed")
			},
		},
		{
			uc: "with unexpected response code from server",
			hydrator: &genericHydrator{
				name: "hydrator",
				e:    endpoint.Endpoint{URL: srv.URL},
			},
			subject: &subject.Subject{ID: "Foo", Attributes: map[string]any{"bar": "baz"}},
			instructServer: func(t *testing.T) {
				t.Helper()

				responseCode = http.StatusInternalServerError
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, hydrationEndpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "unexpected response code")
			},
		},
		{
			uc: "without payload",
			hydrator: &genericHydrator{
				name: "test-hydrator",
				e:    endpoint.Endpoint{URL: srv.URL + "/{{ .Subject.ID }}"},
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
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, hydrationEndpointCalled)

				require.NoError(t, err)

				assert.Len(t, sub.Attributes, 1)
			},
		},
		{
			uc: "without payload, but with cache",
			hydrator: &genericHydrator{
				name: "test-hydrator",
				e:    endpoint.Endpoint{URL: srv.URL + "/{{ .Subject.ID }}"},
				ttl:  10 * time.Second,
			},
			subject: &subject.Subject{ID: "Foo", Attributes: map[string]any{"bar": "baz"}},
			configureCache: func(t *testing.T, cch *mocks.MockCache, hydrator *genericHydrator, sub *subject.Subject) {
				t.Helper()

				key, err := hydrator.calculateCacheKey(sub)
				require.NoError(t, err)

				cch.On("Get", key).Return(nil)
				cch.On("Set", key, mock.MatchedBy(func(val *hydrationData) bool {
					return val != nil && val.payload == "Hi from endpoint"
				}), hydrator.ttl)
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
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, hydrationEndpointCalled)

				require.NoError(t, err)

				assert.Len(t, sub.Attributes, 2)
			},
		},
		{
			uc: "with rendered payload and headers, as well as forwarded headers and cookies",
			hydrator: &genericHydrator{
				name: "test-hydrator",
				e: endpoint.Endpoint{
					URL: srv.URL + "/{{ .Subject.ID }}",
					Headers: map[string]string{
						"Content-Type": "application/json",
						"Accept":       "application/json",
						"X-Bar":        "{{ .Subject.Attributes.bar }}",
					},
				},
				payload: func() template.Template {
					tpl, _ := template.New(`{ "user_id": {{ quote .Subject.ID }}}`)

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

					assert.Equal(t, "/Foo", req.URL.Path)
					assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
					assert.Equal(t, "application/json", req.Header.Get("Accept"))
					assert.Equal(t, "baz", req.Header.Get("X-Bar"))
					assert.Equal(t, "Hi Foo", req.Header.Get("X-Bar-Foo"))
					cookie, err := req.Cookie("X-Foo-Session")
					require.NoError(t, err)
					assert.Equal(t, "Foo-Session-Value", cookie.Value)

					content, err := io.ReadAll(req.Body)
					require.NoError(t, err)

					assert.JSONEq(t, `{"user_id": "Foo"}`, string(content))
				}

				responseContentType = "application/json"
				responseContent = []byte(`{ "baz": "foo" }`)
				responseCode = http.StatusOK
			},
			configureContext: func(t *testing.T, ctx *heimdallmocks.MockContext) {
				t.Helper()

				ctx.On("RequestHeader", "X-Bar-Foo").
					Return("Hi Foo")
				ctx.On("RequestCookie", "X-Foo-Session").
					Return("Foo-Session-Value")
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, hydrationEndpointCalled)

				require.NoError(t, err)

				assert.Len(t, sub.Attributes, 2)
				entry := sub.Attributes["test-hydrator"]
				assert.Len(t, entry, 1)
				assert.Contains(t, entry, "baz")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			hydrationEndpointCalled = false
			responseContentType = ""
			responseContent = nil

			checkRequest = func(*http.Request) { t.Helper() }

			instructServer := x.IfThenElse(tc.instructServer != nil,
				tc.instructServer,
				func(t *testing.T) { t.Helper() })

			configureContext := x.IfThenElse(tc.configureContext != nil,
				tc.configureContext,
				func(t *testing.T, ctx *heimdallmocks.MockContext) { t.Helper() })

			configureCache := x.IfThenElse(tc.configureCache != nil,
				tc.configureCache,
				func(t *testing.T, ctx *mocks.MockCache, auth *genericHydrator, sub *subject.Subject) {
					t.Helper()
				})

			cch := &mocks.MockCache{}

			ctx := &heimdallmocks.MockContext{}
			ctx.On("AppContext").Return(cache.WithContext(context.Background(), cch))

			configureContext(t, ctx)
			configureCache(t, cch, tc.hydrator, tc.subject)
			instructServer(t)

			// WHEN
			err := tc.hydrator.Execute(ctx, tc.subject)

			// THEN
			tc.assert(t, err, tc.subject)

			ctx.AssertExpectations(t)
			cch.AssertExpectations(t)
		})
	}
}
