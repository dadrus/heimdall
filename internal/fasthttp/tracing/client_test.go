package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/opentracing/opentracing-go/mocktracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"

	"github.com/dadrus/heimdall/internal/x"
)

func TestWrappedClientDoTimeout(t *testing.T) {
	t.Parallel()

	var responseCode int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(responseCode)
	}))
	defer srv.Close()

	srvURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc                 string
		tracer             *mocktracer.MockTracer
		timeout            time.Duration
		serverResponseCode int
		assert             func(t *testing.T, err error, req *fasthttp.Request, resp *fasthttp.Response,
			spans []*mocktracer.MockSpan)
	}{
		{
			uc:                 "without tracer",
			serverResponseCode: http.StatusOK,
			timeout:            10 * time.Second,
			assert: func(t *testing.T, err error, req *fasthttp.Request, resp *fasthttp.Response,
				spans []*mocktracer.MockSpan,
			) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode())

				assert.Empty(t, spans)
			},
		},
		{
			uc:                 "with tracer and error while communicating with the server",
			tracer:             mocktracer.New(),
			serverResponseCode: http.StatusOK,
			timeout:            1 * time.Nanosecond,
			assert: func(t *testing.T, err error, req *fasthttp.Request, resp *fasthttp.Response,
				spans []*mocktracer.MockSpan,
			) {
				t.Helper()

				require.Error(t, err)

				assert.Len(t, spans, 2)
				assert.Equal(t, srvURL.Host+" /foobar", spans[0].OperationName)
				assert.Empty(t, spans[0].Tags())
				assert.Empty(t, spans[0].Logs())

				assert.Equal(t, "HTTP GET", spans[1].OperationName)
				assert.Len(t, spans[1].Tags(), 5)
				assert.Equal(t, ext.SpanKindEnum("client"), spans[1].Tag("span.kind"))
				assert.Equal(t, "net/http", spans[1].Tag("component"))
				assert.Equal(t, "GET", spans[1].Tag("http.method"))
				assert.Equal(t, srvURL.String()+"/foobar", spans[1].Tag("http.url"))
				assert.Equal(t, true, spans[1].Tag("error"))

				assert.Empty(t, spans[1].Logs())
			},
		},
		{
			uc:                 "with tracer and successful server response",
			tracer:             mocktracer.New(),
			serverResponseCode: http.StatusOK,
			timeout:            10 * time.Second,
			assert: func(t *testing.T, err error, req *fasthttp.Request, resp *fasthttp.Response,
				spans []*mocktracer.MockSpan,
			) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode())

				assert.Len(t, spans, 2)
				assert.Equal(t, srvURL.Host+" /foobar", spans[0].OperationName)
				assert.Empty(t, spans[0].Tags())
				assert.Empty(t, spans[0].Logs())

				assert.Equal(t, "HTTP GET", spans[1].OperationName)
				assert.Len(t, spans[1].Tags(), 5)
				assert.Equal(t, ext.SpanKindEnum("client"), spans[1].Tag("span.kind"))
				assert.Equal(t, "net/http", spans[1].Tag("component"))
				assert.Equal(t, "GET", spans[1].Tag("http.method"))
				assert.Equal(t, srvURL.String()+"/foobar", spans[1].Tag("http.url"))
				assert.Equal(t, uint16(http.StatusOK), spans[1].Tag("http.status_code"))

				assert.Empty(t, spans[1].Logs())
			},
		},
		{
			uc:                 "with tracer and error server response",
			tracer:             mocktracer.New(),
			serverResponseCode: http.StatusInternalServerError,
			timeout:            10 * time.Second,
			assert: func(t *testing.T, err error, req *fasthttp.Request, resp *fasthttp.Response,
				spans []*mocktracer.MockSpan,
			) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusInternalServerError, resp.StatusCode())

				assert.Len(t, spans, 2)
				assert.Equal(t, srvURL.Host+" /foobar", spans[0].OperationName)
				assert.Empty(t, spans[0].Tags())
				assert.Empty(t, spans[0].Logs())

				assert.Equal(t, "HTTP GET", spans[1].OperationName)
				assert.Len(t, spans[1].Tags(), 6)
				assert.Equal(t, ext.SpanKindEnum("client"), spans[1].Tag("span.kind"))
				assert.Equal(t, "net/http", spans[1].Tag("component"))
				assert.Equal(t, "GET", spans[1].Tag("http.method"))
				assert.Equal(t, srvURL.String()+"/foobar", spans[1].Tag("http.url"))
				assert.Equal(t, uint16(http.StatusInternalServerError), spans[1].Tag("http.status_code"))
				assert.Equal(t, true, spans[1].Tag("error"))

				assert.Empty(t, spans[1].Logs())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			if tc.tracer != nil {
				opentracing.SetGlobalTracer(tc.tracer)
			}

			responseCode = tc.serverResponseCode

			req := fasthttp.AcquireRequest()
			defer fasthttp.ReleaseRequest(req)

			uri := fasthttp.AcquireURI()
			defer fasthttp.ReleaseURI(uri)
			uri.SetHost(srvURL.Host)
			uri.SetScheme(srvURL.Scheme)
			uri.SetPath("/foobar")

			req.Header.SetMethod("GET")
			req.SetURI(uri)

			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseResponse(resp)

			client := NewClient(&fasthttp.Client{})

			// WHEN
			err = client.DoTimeout(context.Background(), req, resp, tc.timeout)

			// THEN
			tc.assert(t, err, req, resp, x.IfThenElseExec(tc.tracer != nil,
				func() []*mocktracer.MockSpan { return tc.tracer.FinishedSpans() },
				func() []*mocktracer.MockSpan { return nil }))
		})
	}
}
