package httpendpoint

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache/memory"
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
			uc:   "with unknown field",
			conf: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to decode")
			},
		},
		{
			uc:   "without endpoints",
			conf: []byte(`watch_interval: 5s`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no endpoints configured")
			},
		},
		{
			uc: "with watch interval and unsupported endpoint property configured",
			conf: []byte(`
watch_interval: 5s
endpoints:
- foo: bar
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to decode")
			},
		},
		{
			uc: "with one endpoint without url",
			conf: []byte(`
endpoints:
- method: POST
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to initialize #0 http_endpoint")
			},
		},
		{
			uc: "with only one endpoint and its url configured",
			conf: []byte(`
endpoints:
- url: https://foo.bar
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prov)
				assert.NotNil(t, prov.s)
				assert.NotNil(t, prov.q)
				assert.NotNil(t, prov.cancel)
				assert.False(t, prov.s.IsRunning())
				assert.Len(t, prov.s.Jobs(), 1)
				job := prov.s.Jobs()[0]
				assert.False(t, job.IsRunning())
			},
		},
		{
			uc: "with two endpoints and watch interval configured",
			conf: []byte(`
watch_interval: 5m
endpoints:
- url: https://foo.bar
- url: https://bar.foo
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prov)
				assert.NotNil(t, prov.s)
				assert.NotNil(t, prov.q)
				assert.NotNil(t, prov.cancel)
				assert.False(t, prov.s.IsRunning())
				assert.Len(t, prov.s.Jobs(), 2)
				assert.False(t, prov.s.Jobs()[0].IsRunning())
				assert.False(t, prov.s.Jobs()[1].IsRunning())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			providerConf, err := testsupport.DecodeTestConfig(tc.conf)
			require.NoError(t, err)

			queue := make(event.RuleSetChangedEventQueue, 10)

			// WHEN
			prov, err := newProvider(providerConf, memory.New(), queue, log.Logger)

			// THEN
			tc.assert(t, err, prov)
		})
	}
}

func TestProviderLifecycle(t *testing.T) { //nolint:maintidx
	t.Parallel()

	type ResponseWriter func(t *testing.T, w http.ResponseWriter)

	var (
		writeResponse ResponseWriter
		requestCount  int
		rcm           sync.Mutex
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rcm.Lock()
		requestCount++
		rcm.Unlock()

		writeResponse(t, w)
	}))

	defer srv.Close()

	for _, tc := range []struct {
		uc            string
		conf          []byte
		writeResponse ResponseWriter
		assert        func(t *testing.T, logs fmt.Stringer, queue event.RuleSetChangedEventQueue)
	}{
		{
			uc: "with rule set loading error due to DNS error",
			conf: []byte(`
endpoints:
- url: https://foo.bar.local/rules.yaml
`),
			assert: func(t *testing.T, logs fmt.Stringer, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				messages := logs.String()
				assert.Contains(t, messages, "name resolution")
				assert.Contains(t, messages, "No updates received")

				require.Len(t, queue, 0)
			},
		},
		{
			uc: "with rule set loading error due server error response",
			conf: []byte(`
endpoints:
- url: ` + srv.URL + `
`),
			writeResponse: func(t *testing.T, w http.ResponseWriter) {
				t.Helper()

				w.WriteHeader(http.StatusBadRequest)
			},
			assert: func(t *testing.T, logs fmt.Stringer, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				messages := logs.String()
				assert.Contains(t, messages, "response code: 400")
				assert.Contains(t, messages, "No updates received")

				require.Len(t, queue, 0)
			},
		},
		{
			uc: "with empty server response",
			conf: []byte(`
endpoints:
- url: ` + srv.URL + `
`),
			writeResponse: func(t *testing.T, w http.ResponseWriter) {
				t.Helper()

				w.WriteHeader(http.StatusOK)
			},
			assert: func(t *testing.T, logs fmt.Stringer, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				assert.Equal(t, 1, requestCount)
				assert.Contains(t, logs.String(), "No updates received")

				require.Len(t, queue, 0)
			},
		},
		{
			uc: "with not empty server response and without watch interval",
			conf: []byte(`
endpoints:
- url: ` + srv.URL + `
`),
			writeResponse: func(t *testing.T, w http.ResponseWriter) {
				t.Helper()

				w.Header().Set("Content-Type", "application/yaml")
				_, err := w.Write([]byte("- id: foo"))
				require.NoError(t, err)
			},
			assert: func(t *testing.T, logs fmt.Stringer, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				time.Sleep(600 * time.Millisecond)

				assert.Equal(t, 1, requestCount)
				assert.NotContains(t, logs.String(), "No updates received")

				require.Len(t, queue, 1)

				evt := <-queue
				assert.Contains(t, evt.Src, "http_endpoint:"+srv.URL)
				assert.Len(t, evt.RuleSet, 1)
				assert.Equal(t, "foo", evt.RuleSet[0].ID)
				assert.Equal(t, event.Create, evt.ChangeType)
			},
		},
		{
			uc: "with not empty server response and with watch interval",
			conf: []byte(`
watch_interval: 250ms
endpoints:
  - url: ` + srv.URL + `
`),
			writeResponse: func(t *testing.T, w http.ResponseWriter) {
				t.Helper()

				w.Header().Set("Content-Type", "application/yaml")
				_, err := w.Write([]byte("- id: bar"))
				require.NoError(t, err)
			},
			assert: func(t *testing.T, logs fmt.Stringer, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				time.Sleep(600 * time.Millisecond)

				assert.Equal(t, 3, requestCount)
				assert.Contains(t, logs.String(), "No updates received")

				require.Len(t, queue, 1)

				evt := <-queue
				assert.Contains(t, evt.Src, "http_endpoint:"+srv.URL)
				assert.Len(t, evt.RuleSet, 1)
				assert.Equal(t, "bar", evt.RuleSet[0].ID)
				assert.Equal(t, event.Create, evt.ChangeType)
			},
		},
		{
			uc: "first request successful, second request with 500, successive requests successful without changes",
			conf: []byte(`
watch_interval: 250ms
endpoints:
  - url: ` + srv.URL + `
`),
			writeResponse: func() ResponseWriter {
				callIdx := 1

				return func(t *testing.T, w http.ResponseWriter) {
					t.Helper()

					switch callIdx {
					case 1:
						w.Header().Set("Content-Type", "application/yaml")
						_, err := w.Write([]byte("- id: bar"))
						require.NoError(t, err)
					case 2:
						w.WriteHeader(http.StatusInternalServerError)
					default:
						w.Header().Set("Content-Type", "application/yaml")
						_, err := w.Write([]byte("- id: bar"))
						require.NoError(t, err)
					}

					callIdx++
				}
			}(),
			assert: func(t *testing.T, logs fmt.Stringer, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				time.Sleep(1000 * time.Millisecond)

				assert.True(t, requestCount >= 4)
				assert.Contains(t, logs.String(), "No updates received")

				require.Len(t, queue, 3)

				evt := <-queue
				assert.Contains(t, evt.Src, "http_endpoint:"+srv.URL)
				assert.Len(t, evt.RuleSet, 1)
				assert.Equal(t, "bar", evt.RuleSet[0].ID)
				assert.Equal(t, event.Create, evt.ChangeType)

				evt = <-queue
				assert.Contains(t, evt.Src, "http_endpoint:"+srv.URL)
				assert.Len(t, evt.RuleSet, 0)
				assert.Equal(t, event.Remove, evt.ChangeType)

				evt = <-queue
				assert.Contains(t, evt.Src, "http_endpoint:"+srv.URL)
				assert.Len(t, evt.RuleSet, 1)
				assert.Equal(t, "bar", evt.RuleSet[0].ID)
				assert.Equal(t, event.Create, evt.ChangeType)
			},
		},
		{
			uc: "successive changes to the rule set in each retrieval",
			conf: []byte(`
watch_interval: 200ms
endpoints:
  - url: ` + srv.URL + `
`),
			writeResponse: func() ResponseWriter {
				callIdx := 1

				return func(t *testing.T, w http.ResponseWriter) {
					t.Helper()

					switch callIdx {
					case 1:
						w.Header().Set("Content-Type", "application/yaml")
						_, err := w.Write([]byte("- id: bar"))
						require.NoError(t, err)
					case 2:
						w.Header().Set("Content-Type", "application/yaml")
						_, err := w.Write([]byte("- id: baz"))
						require.NoError(t, err)
					case 3:
						w.Header().Set("Content-Type", "application/yaml")
						_, err := w.Write([]byte("- id: foo"))
						require.NoError(t, err)
					default:
						w.Header().Set("Content-Type", "application/yaml")
						_, err := w.Write([]byte("- id: foz"))
						require.NoError(t, err)
					}

					callIdx++
				}
			}(),
			assert: func(t *testing.T, logs fmt.Stringer, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				time.Sleep(1200 * time.Millisecond)

				assert.True(t, requestCount >= 4)
				assert.Contains(t, logs.String(), "No updates received")

				require.Len(t, queue, 7)

				evt := <-queue
				assert.Contains(t, evt.Src, "http_endpoint:"+srv.URL)
				assert.Len(t, evt.RuleSet, 1)
				assert.Equal(t, "bar", evt.RuleSet[0].ID)
				assert.Equal(t, event.Create, evt.ChangeType)

				evt = <-queue
				assert.Contains(t, evt.Src, "http_endpoint:"+srv.URL)
				assert.Len(t, evt.RuleSet, 0)
				assert.Equal(t, event.Remove, evt.ChangeType)

				evt = <-queue
				assert.Contains(t, evt.Src, "http_endpoint:"+srv.URL)
				assert.Len(t, evt.RuleSet, 1)
				assert.Equal(t, "baz", evt.RuleSet[0].ID)
				assert.Equal(t, event.Create, evt.ChangeType)

				evt = <-queue
				assert.Contains(t, evt.Src, "http_endpoint:"+srv.URL)
				assert.Len(t, evt.RuleSet, 0)
				assert.Equal(t, event.Remove, evt.ChangeType)

				evt = <-queue
				assert.Contains(t, evt.Src, "http_endpoint:"+srv.URL)
				assert.Len(t, evt.RuleSet, 1)
				assert.Equal(t, "foo", evt.RuleSet[0].ID)
				assert.Equal(t, event.Create, evt.ChangeType)

				evt = <-queue
				assert.Contains(t, evt.Src, "http_endpoint:"+srv.URL)
				assert.Len(t, evt.RuleSet, 0)
				assert.Equal(t, event.Remove, evt.ChangeType)

				evt = <-queue
				assert.Contains(t, evt.Src, "http_endpoint:"+srv.URL)
				assert.Len(t, evt.RuleSet, 1)
				assert.Equal(t, "foz", evt.RuleSet[0].ID)
				assert.Equal(t, event.Create, evt.ChangeType)
			},
		},
		{
			uc: "response is cached",
			conf: []byte(`
watch_interval: 250ms
endpoints:
  - url: ` + srv.URL + `
`),
			writeResponse: func(t *testing.T, w http.ResponseWriter) {
				t.Helper()

				w.Header().Set("Expires", time.Now().Add(20*time.Second).UTC().Format(http.TimeFormat))
				w.Header().Set("Content-Type", "application/yaml")
				_, err := w.Write([]byte("- id: bar"))
				require.NoError(t, err)
			},
			assert: func(t *testing.T, logs fmt.Stringer, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				time.Sleep(1 * time.Second)

				assert.Equal(t, 1, requestCount)
				assert.Equal(t, 3, strings.Count(logs.String(), "No updates received"))
				require.Len(t, queue, 1)

				evt := <-queue
				assert.Contains(t, evt.Src, "http_endpoint:"+srv.URL)
				assert.Len(t, evt.RuleSet, 1)
				assert.Equal(t, "bar", evt.RuleSet[0].ID)
				assert.Equal(t, event.Create, evt.ChangeType)
			},
		},
		{
			uc: "response is not cached, as caching is disabled",
			conf: []byte(`
watch_interval: 250ms
endpoints:
  - url: ` + srv.URL + `
    enable_http_cache: false
`),
			writeResponse: func(t *testing.T, w http.ResponseWriter) {
				t.Helper()

				w.Header().Set("Expires", time.Now().Add(20*time.Second).UTC().Format(http.TimeFormat))
				w.Header().Set("Content-Type", "application/yaml")
				_, err := w.Write([]byte("- id: bar"))
				require.NoError(t, err)
			},
			assert: func(t *testing.T, logs fmt.Stringer, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				time.Sleep(1 * time.Second)

				assert.Equal(t, 4, requestCount)

				noUpdatesCount := strings.Count(logs.String(), "No updates received")
				assert.Equal(t, noUpdatesCount, 3)

				require.Len(t, queue, 1)

				evt := <-queue
				assert.Contains(t, evt.Src, "http_endpoint:"+srv.URL)
				assert.Len(t, evt.RuleSet, 1)
				assert.Equal(t, "bar", evt.RuleSet[0].ID)
				assert.Equal(t, event.Create, evt.ChangeType)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			requestCount = 0

			providerConf, err := testsupport.DecodeTestConfig(tc.conf)
			require.NoError(t, err)

			queue := make(event.RuleSetChangedEventQueue, 10)
			defer close(queue)

			logs := &strings.Builder{}
			prov, err := newProvider(providerConf, memory.New(), queue, zerolog.New(logs))
			require.NoError(t, err)

			ctx := context.Background()

			writeResponse = x.IfThenElse(tc.writeResponse != nil,
				tc.writeResponse,
				func(t *testing.T, w http.ResponseWriter) {
					t.Helper()

					w.WriteHeader(http.StatusOK)
				})

			// WHEN
			err = prov.Start(ctx)

			defer prov.Stop(ctx) //nolint:errcheck

			// THEN
			require.NoError(t, err)
			tc.assert(t, logs, queue)
		})
	}
}
