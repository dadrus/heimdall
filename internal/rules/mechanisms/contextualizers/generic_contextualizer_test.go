package contextualizers

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

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/endpoint"
	"github.com/dadrus/heimdall/internal/heimdall"
	heimdallmocks "github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
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
			assert: func(t *testing.T, err error, _ *genericContextualizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to validate endpoint")
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
				val, err := contextualizer.payload.Render(nil, &subject.Subject{ID: "baz"})
				require.NoError(t, err)
				assert.Equal(t, "bar", val)
				assert.Empty(t, contextualizer.fwdCookies)
				assert.Empty(t, contextualizer.fwdHeaders)
				assert.Equal(t, defaultTTL, contextualizer.ttl)

				assert.Equal(t, "contextualizer", contextualizer.HandlerID())
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
`),
			assert: func(t *testing.T, err error, contextualizer *genericContextualizer) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, contextualizer)

				assert.Equal(t, "http://bar.foo", contextualizer.e.URL)
				require.NotNil(t, contextualizer.payload)
				val, err := contextualizer.payload.Render(nil, &subject.Subject{ID: "baz"})
				require.NoError(t, err)
				assert.Equal(t, "baz", val)
				assert.Len(t, contextualizer.fwdCookies, 1)
				assert.Contains(t, contextualizer.fwdCookies, "My-Foo-Session")
				assert.Len(t, contextualizer.fwdHeaders, 2)
				assert.Contains(t, contextualizer.fwdHeaders, "X-User-ID")
				assert.Contains(t, contextualizer.fwdHeaders, "X-Foo-Bar")
				assert.Equal(t, 5*time.Second, contextualizer.ttl)

				assert.Equal(t, "contextualizer", contextualizer.HandlerID())
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
				assert.Equal(t, "contextualizer1", configured.HandlerID())
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
			assert: func(t *testing.T, err error, prototype *genericContextualizer, configured *genericContextualizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
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
				val, err := configured.payload.Render(nil, &subject.Subject{ID: "baz"})
				require.NoError(t, err)
				assert.Equal(t, "foo", val)
				assert.Equal(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Equal(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, "contextualizer2", configured.HandlerID())
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
				val, err := configured.payload.Render(nil, &subject.Subject{ID: "baz"})
				require.NoError(t, err)
				assert.Equal(t, "foo", val)
				assert.NotEqual(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Len(t, configured.fwdHeaders, 1)
				assert.Contains(t, configured.fwdHeaders, "Foo-Bar")
				assert.Equal(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, "contextualizer3", configured.HandlerID())
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
				assert.Equal(t, "contextualizer4", configured.HandlerID())
			},
		},
		{
			uc: "with everything reconfigured",
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
`),
			config: []byte(`
payload: foo
forward_headers:
  - Foo-Bar
forward_cookies:
  - Foo-Session
cache_ttl: 15s
`),
			assert: func(t *testing.T, err error, prototype *genericContextualizer, configured *genericContextualizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.id, configured.id)
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
				assert.Equal(t, "contextualizer5", configured.HandlerID())
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

// nolint: maintidx
func TestGenericContextualizerExecute(t *testing.T) {
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
		contextualizer   *genericContextualizer
		subject          *subject.Subject
		instructServer   func(t *testing.T)
		configureContext func(t *testing.T, ctx *heimdallmocks.MockContext)
		configureCache   func(t *testing.T, cch *mocks.MockCache, contextualizer *genericContextualizer,
			sub *subject.Subject)
		assert func(t *testing.T, err error, sub *subject.Subject)
	}{
		{
			uc:             "fails due to nil subject",
			contextualizer: &genericContextualizer{id: "contextualizer", e: endpoint.Endpoint{URL: srv.URL}},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, hydrationEndpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "'nil' subject")

				var identifier interface{ HandlerID() string }
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "contextualizer", identifier.HandlerID())
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
			configureCache: func(t *testing.T, cch *mocks.MockCache, contextualizer *genericContextualizer,
				sub *subject.Subject,
			) {
				t.Helper()

				key := contextualizer.calculateCacheKey(sub)
				cch.On("Get", key).Return(&contextualizerData{payload: "Hi Foo"})
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, hydrationEndpointCalled)

				require.NoError(t, err)
				assert.Len(t, sub.Attributes, 2)
				assert.Equal(t, sub.Attributes["contextualizer"], "Hi Foo")
			},
		},
		{
			uc: "with wrong object type in cache",
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
			configureCache: func(t *testing.T, cch *mocks.MockCache, contextualizer *genericContextualizer,
				sub *subject.Subject,
			) {
				t.Helper()

				key := contextualizer.calculateCacheKey(sub)
				cch.On("Get", key).Return("Hi Foo")
				cch.On("Delete", key)
				cch.On("Set", key, mock.MatchedBy(func(val *contextualizerData) bool {
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
				assert.Equal(t, sub.Attributes["contextualizer"], "Hi from endpoint")
			},
		},
		{
			uc: "with error in payload rendering",
			contextualizer: &genericContextualizer{
				id: "contextualizer1",
				e:  endpoint.Endpoint{URL: srv.URL},
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

				var identifier interface{ HandlerID() string }
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "contextualizer1", identifier.HandlerID())
			},
		},
		{
			uc: "with communication error (dns)",
			contextualizer: &genericContextualizer{
				id: "contextualizer2",
				e:  endpoint.Endpoint{URL: "http://heimdall.test.local"},
			},
			subject: &subject.Subject{ID: "Foo", Attributes: map[string]any{"bar": "baz"}},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.False(t, hydrationEndpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "contextualizer endpoint failed")

				var identifier interface{ HandlerID() string }
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "contextualizer2", identifier.HandlerID())
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
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				assert.True(t, hydrationEndpointCalled)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "unexpected response code")

				var identifier interface{ HandlerID() string }
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "contextualizer3", identifier.HandlerID())
			},
		},
		{
			uc: "without payload",
			contextualizer: &genericContextualizer{
				id: "test-contextualizer",
				e:  endpoint.Endpoint{URL: srv.URL + "/{{ .Subject.ID }}"},
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
			contextualizer: &genericContextualizer{
				id:  "test-contextualizer",
				e:   endpoint.Endpoint{URL: srv.URL + "/{{ .Subject.ID }}"},
				ttl: 10 * time.Second,
			},
			subject: &subject.Subject{ID: "Foo", Attributes: map[string]any{"bar": "baz"}},
			configureCache: func(t *testing.T, cch *mocks.MockCache, contextualizer *genericContextualizer,
				sub *subject.Subject,
			) {
				t.Helper()

				key := contextualizer.calculateCacheKey(sub)
				cch.On("Get", key).Return(nil)
				cch.On("Set", key, mock.MatchedBy(func(val *contextualizerData) bool {
					return val != nil && val.payload == "Hi from endpoint"
				}), contextualizer.ttl)
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
			contextualizer: &genericContextualizer{
				id: "test-contextualizer",
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
				entry := sub.Attributes["test-contextualizer"]
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
				func(t *testing.T, ctx *mocks.MockCache, auth *genericContextualizer, sub *subject.Subject) {
					t.Helper()
				})

			cch := &mocks.MockCache{}

			ctx := &heimdallmocks.MockContext{}
			ctx.On("AppContext").Return(cache.WithContext(context.Background(), cch))

			configureContext(t, ctx)
			configureCache(t, cch, tc.contextualizer, tc.subject)
			instructServer(t)

			// WHEN
			err := tc.contextualizer.Execute(ctx, tc.subject)

			// THEN
			tc.assert(t, err, tc.subject)

			ctx.AssertExpectations(t)
			cch.AssertExpectations(t)
		})
	}
}
