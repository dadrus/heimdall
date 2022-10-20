package httpendpoint

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache/mocks"
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

	type ResponseWriter func(t *testing.T, w http.ResponseWriter)

	var writeResponse ResponseWriter

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

				assert.Len(t, queue, 1)

				evt := <-queue
				assert.Contains(t, evt.Src, "http_endpoint:https://foo.bar.local/rules.yaml")
				assert.Empty(t, evt.RuleSet)
				assert.Equal(t, event.Remove, evt.ChangeType)
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

				assert.Len(t, queue, 1)

				evt := <-queue
				assert.Contains(t, evt.Src, "http_endpoint:"+srv.URL)
				assert.Empty(t, evt.RuleSet)
				assert.Equal(t, event.Remove, evt.ChangeType)
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

				assert.Len(t, queue, 1)

				evt := <-queue
				assert.Contains(t, evt.Src, "http_endpoint:"+srv.URL)
				assert.Empty(t, evt.RuleSet)
				assert.Equal(t, event.Remove, evt.ChangeType)
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

				time.Sleep(1100 * time.Millisecond)

				assert.Len(t, queue, 1)

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

				time.Sleep(1100 * time.Millisecond)

				assert.Len(t, queue, 5)

				evt1 := <-queue
				evt2 := <-queue
				evt3 := <-queue
				evt4 := <-queue
				evt5 := <-queue
				assert.Contains(t, evt1.Src, "http_endpoint:"+srv.URL)
				assert.Len(t, evt1.RuleSet, 1)
				assert.Equal(t, "bar", evt1.RuleSet[0].ID)
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
			providerConf, err := testsupport.DecodeTestConfig(tc.conf)
			require.NoError(t, err)

			cch := &mocks.MockCache{}
			queue := make(event.RuleSetChangedEventQueue, 10)
			defer close(queue)

			logs := &strings.Builder{}
			prov, err := newProvider(providerConf, cch, queue, zerolog.New(logs))
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
