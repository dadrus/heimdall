package httpendpoint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/endpoint"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/dadrus/heimdall/internal/x"
)

func TestNewProvider(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		conf   []byte
		assert func(t *testing.T, err error, prov *provider)
	}{
		{
			uc:   "with invalid configuration, unknown field",
			conf: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to decode")
			},
		},
		{
			uc: "with endpoint without url configured",
			conf: []byte(`
endpoint:
  method: POST
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to validate http_endpoint")
			},
		},
		{
			uc: "with unsupported endpoint method configured",
			conf: []byte(`
endpoint:
  url: https://foo.bar
  method: POST
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "only GET is supported")
			},
		},
		{
			uc: "with only endpoint and its url configured",
			conf: []byte(`
endpoint:
  url: https://foo.bar
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prov)
				assert.Equal(t, "https://foo.bar", prov.e.URL)
				assert.Equal(t, http.MethodGet, prov.e.Method)
				assert.Equal(t, 0*time.Second, prov.wi)
				assert.NotNil(t, prov.q)
			},
		},
		{
			uc: "with only endpoint, its url and supported method configured",
			conf: []byte(`
endpoint:
  url: https://foo.bar
  method: GET
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prov)
				assert.Equal(t, "https://foo.bar", prov.e.URL)
				assert.Equal(t, http.MethodGet, prov.e.Method)
				assert.Equal(t, 0*time.Second, prov.wi)
				assert.NotNil(t, prov.q)
			},
		},
		{
			uc: "with endpoint and watch interval configured",
			conf: []byte(`
endpoint:
  url: https://foo.bar
watch_interval: 5m
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prov)
				assert.Equal(t, "https://foo.bar", prov.e.URL)
				assert.Equal(t, http.MethodGet, prov.e.Method)
				assert.Equal(t, 5*time.Minute, prov.wi)
				assert.NotNil(t, prov.q)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			providerConf, err := testsupport.DecodeTestConfig(tc.conf)
			require.NoError(t, err)

			cch := &mocks.MockCache{}
			queue := make(event.RuleSetChangedEventQueue, 10)

			// WHEN
			prov, err := newProvider(providerConf, cch, queue, log.Logger)

			// THEN
			tc.assert(t, err, prov)
		})
	}
}

func TestProviderLifecycle(t *testing.T) {
	t.Parallel()

	type (
		RequestChecker func(t *testing.T, r *http.Request)
		ResponseWriter func(t *testing.T, w http.ResponseWriter)
	)

	var (
		checkRequest  RequestChecker
		writeResponse ResponseWriter
		callCount     int
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		checkRequest(t, r)
		writeResponse(t, w)
	}))

	defer srv.Close()

	for _, tc := range []struct {
		uc            string
		ep            endpoint.Endpoint
		watchInterval time.Duration
		checkRequest  RequestChecker
		writeResponse ResponseWriter
		assert        func(t *testing.T, err error, queue event.RuleSetChangedEventQueue)
	}{
		{
			uc: "with initial rule set loading error due to DNS error",
			ep: endpoint.Endpoint{URL: "https://foo.bar.local/rules.yaml", Method: http.MethodGet},
			assert: func(t *testing.T, err error, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				defer close(queue)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "endpoint failed")
				assert.Len(t, queue, 0)
			},
		},
		{
			uc: "with initial rule set loading error due server error response",
			ep: endpoint.Endpoint{URL: srv.URL, Method: http.MethodGet},
			writeResponse: func(t *testing.T, w http.ResponseWriter) {
				t.Helper()

				w.WriteHeader(http.StatusBadRequest)
			},
			assert: func(t *testing.T, err error, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				assert.Equal(t, 1, callCount)

				defer close(queue)

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "unexpected response")
				assert.Len(t, queue, 0)
			},
		},
		{
			uc: "with empty server response",
			ep: endpoint.Endpoint{URL: srv.URL, Method: http.MethodGet},
			writeResponse: func(t *testing.T, w http.ResponseWriter) {
				t.Helper()

				w.WriteHeader(http.StatusOK)
			},
			assert: func(t *testing.T, err error, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				assert.Equal(t, 1, callCount)

				defer close(queue)

				require.NoError(t, err)
				assert.Len(t, queue, 0)
			},
		},
		{
			uc: "with not empty server response and without watch interval",
			ep: endpoint.Endpoint{URL: srv.URL, Method: http.MethodGet},
			writeResponse: func(t *testing.T, w http.ResponseWriter) {
				t.Helper()

				_, err := w.Write([]byte("hello foo"))
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				defer close(queue)

				time.Sleep(1 * time.Second)

				assert.Equal(t, 1, callCount)

				require.NoError(t, err)
				assert.Len(t, queue, 1)

				evt := <-queue
				assert.Contains(t, evt.Src, "http_endpoint:"+srv.URL)
				assert.Equal(t, []byte("hello foo"), evt.Definition)
				assert.Equal(t, event.Create, evt.ChangeType)
			},
		},
		{
			uc:            "with not empty server response and with watch interval",
			watchInterval: 250 * time.Millisecond,
			ep:            endpoint.Endpoint{URL: srv.URL, Method: http.MethodGet},
			writeResponse: func(t *testing.T, w http.ResponseWriter) {
				t.Helper()

				_, err := w.Write([]byte("hello foo"))
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				defer close(queue)

				time.Sleep(1100 * time.Millisecond)

				assert.Equal(t, 5, callCount)

				require.NoError(t, err)
				assert.Len(t, queue, 5)

				evt1 := <-queue
				evt2 := <-queue
				evt3 := <-queue
				evt4 := <-queue
				evt5 := <-queue
				assert.Contains(t, evt1.Src, "http_endpoint:"+srv.URL)
				assert.Equal(t, []byte("hello foo"), evt1.Definition)
				assert.Equal(t, event.Create, evt1.ChangeType)
				assert.Equal(t, evt1, evt2)
				assert.Equal(t, evt1, evt3)
				assert.Equal(t, evt1, evt4)
				assert.Equal(t, evt1, evt5)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			callCount = 0
			ctx := context.Background()
			queue := make(event.RuleSetChangedEventQueue, 10)
			prov := &provider{
				e:         tc.ep,
				wi:        tc.watchInterval,
				q:         queue,
				l:         log.Logger,
				done:      make(chan struct{}),
				doneWatch: make(chan struct{}),
			}

			checkRequest = x.IfThenElse(tc.checkRequest != nil,
				tc.checkRequest,
				func(t *testing.T, r *http.Request) { t.Helper() })
			writeResponse = x.IfThenElse(tc.writeResponse != nil,
				tc.writeResponse,
				func(t *testing.T, w http.ResponseWriter) {
					t.Helper()

					w.WriteHeader(http.StatusOK)
				})

			// WHEN
			err := prov.Start(ctx)

			defer prov.Stop(ctx)

			// THEN
			tc.assert(t, err, queue)
		})
	}
}
