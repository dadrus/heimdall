package opentelemetry

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"go.opentelemetry.io/otel/trace"

	otelmock "github.com/dadrus/heimdall/internal/x/opentelemetry/mocks"
)

func TestWrappedClientDoTimeout(t *testing.T) {
	t.Parallel()

	mtracer := otelmock.NewMockTracer()
	parentSpanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1},
		SpanID:     trace.SpanID{2},
		TraceFlags: trace.FlagsSampled,
	})
	ctxWithSpan, span := mtracer.Start(
		trace.ContextWithSpanContext(context.Background(), parentSpanContext), "test")

	defer span.End()

	var responseCode int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/foobar", r.URL.Path)
		w.WriteHeader(responseCode)
	}))
	defer srv.Close()

	srvURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc             string
		tracer         *otelmock.MockTracer
		timeout        time.Duration
		ctx            context.Context // nolint: containedctx
		serverResponse int
		assert         func(t *testing.T, err error, req *fasthttp.Request, resp *fasthttp.Response,
			spans []*otelmock.MockSpan)
	}{
		{
			uc:             "request without parent span, resulting in http 200",
			serverResponse: http.StatusOK,
			ctx:            context.Background(),
			timeout:        10 * time.Second,
			assert: func(t *testing.T, err error, req *fasthttp.Request, resp *fasthttp.Response,
				spans []*otelmock.MockSpan,
			) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode())

				assert.Empty(t, spans)
			},
		},
		{
			uc:             "request with parent span, resulting in http 200",
			serverResponse: http.StatusOK,
			ctx:            ctxWithSpan,
			timeout:        10 * time.Second,
			assert: func(t *testing.T, err error, req *fasthttp.Request, resp *fasthttp.Response,
				spans []*otelmock.MockSpan,
			) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode())

				require.Len(t, spans, 1)
				assert.NotEqual(t, parentSpanContext.SpanID(), spans[0].SpanContext().SpanID())
				assert.Equal(t, parentSpanContext.TraceID(), spans[0].SpanContext().TraceID())

				assert.Equal(t, fmt.Sprintf("%s /foobar", srvURL.Host), spans[0].Name)
				assert.Equal(t, trace.SpanKindClient, spans[0].SpanKind)

				attributes := spans[0].Attributes
				assert.Len(t, attributes, 9)
				assert.Contains(t, attributes, semconv.HTTPURLKey.String("/foobar"))
				assert.Contains(t, attributes, semconv.HTTPUserAgentKey.String("test-client"))
				assert.Contains(t, attributes, semconv.HTTPSchemeHTTP)
				assert.Contains(t, attributes, semconv.HTTPHostKey.String(srvURL.Host))
				assert.Contains(t, attributes, semconv.HTTPFlavorHTTP11)
				assert.Contains(t, attributes, semconv.HTTPMethodKey.String("GET"))
				assert.Contains(t, attributes, semconv.HTTPStatusCodeKey.Int64(200))
				assert.Contains(t, attributes, attribute.Int64("status.code", 0))
				assert.Contains(t, attributes, attribute.String("status.message", ""))
			},
		},
		{
			uc:             "request with parent span and error while communicating with the server",
			serverResponse: http.StatusOK,
			ctx:            ctxWithSpan,
			timeout:        1 * time.Nanosecond,
			assert: func(t *testing.T, err error, req *fasthttp.Request, resp *fasthttp.Response,
				spans []*otelmock.MockSpan,
			) {
				t.Helper()

				require.Error(t, err)

				require.Len(t, spans, 1)
				assert.NotEqual(t, parentSpanContext.SpanID(), spans[0].SpanContext().SpanID())
				assert.Equal(t, parentSpanContext.TraceID(), spans[0].SpanContext().TraceID())

				assert.Equal(t, fmt.Sprintf("%s /foobar", srvURL.Host), spans[0].Name)
				assert.Equal(t, trace.SpanKindClient, spans[0].SpanKind)

				attributes := spans[0].Attributes
				assert.Len(t, attributes, 8)
				assert.Contains(t, attributes, semconv.HTTPURLKey.String("/foobar"))
				assert.Contains(t, attributes, semconv.HTTPUserAgentKey.String("test-client"))
				assert.Contains(t, attributes, semconv.HTTPSchemeHTTP)
				assert.Contains(t, attributes, semconv.HTTPHostKey.String(srvURL.Host))
				assert.Contains(t, attributes, semconv.HTTPFlavorHTTP11)
				assert.Contains(t, attributes, semconv.HTTPMethodKey.String("GET"))
				assert.Contains(t, attributes, attribute.Int64("status.code", 1))
				assert.Contains(t, attributes, attribute.String("status.message", "timeout"))
			},
		},
		{
			uc:             "request with parent span and error server response",
			serverResponse: http.StatusInternalServerError,
			ctx:            ctxWithSpan,
			timeout:        10 * time.Second,
			assert: func(t *testing.T, err error, req *fasthttp.Request, resp *fasthttp.Response,
				spans []*otelmock.MockSpan,
			) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusInternalServerError, resp.StatusCode())

				require.Len(t, spans, 1)
				assert.NotEqual(t, parentSpanContext.SpanID(), spans[0].SpanContext().SpanID())
				assert.Equal(t, parentSpanContext.TraceID(), spans[0].SpanContext().TraceID())

				assert.Equal(t, fmt.Sprintf("%s /foobar", srvURL.Host), spans[0].Name)
				assert.Equal(t, trace.SpanKindClient, spans[0].SpanKind)

				attributes := spans[0].Attributes
				assert.Len(t, attributes, 9)
				assert.Contains(t, attributes, semconv.HTTPURLKey.String("/foobar"))
				assert.Contains(t, attributes, semconv.HTTPUserAgentKey.String("test-client"))
				assert.Contains(t, attributes, semconv.HTTPSchemeHTTP)
				assert.Contains(t, attributes, semconv.HTTPHostKey.String(srvURL.Host))
				assert.Contains(t, attributes, semconv.HTTPFlavorHTTP11)
				assert.Contains(t, attributes, semconv.HTTPMethodKey.String("GET"))
				assert.Contains(t, attributes, semconv.HTTPStatusCodeKey.Int64(500))
				assert.Contains(t, attributes, attribute.Int64("status.code", 1))
				assert.Contains(t, attributes, attribute.String("status.message", ""))
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			mtracer.Reset()

			responseCode = tc.serverResponse

			req := fasthttp.AcquireRequest()
			defer fasthttp.ReleaseRequest(req)

			uri := fasthttp.AcquireURI()
			defer fasthttp.ReleaseURI(uri)
			uri.SetHost(srvURL.Host)
			uri.SetScheme(srvURL.Scheme)
			uri.SetPath("/foobar")

			req.Header.SetMethod("GET")
			req.Header.SetHost(srvURL.Host)
			req.Header.SetUserAgent("test-client")
			req.SetURI(uri)

			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseResponse(resp)

			client := NewClient(&fasthttp.Client{})

			// WHEN
			err = client.DoTimeout(tc.ctx, req, resp, tc.timeout)

			// THEN
			tc.assert(t, err, req, resp, mtracer.FinishedSpans)
		})
	}
}
