package opentelemetry

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/valyala/fasthttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName    = "github.com/dadrus/heimdall/internal/fasthttp/middleware/opentelemetry"
	tracerVersion = "semver:0.1.0"
)

func newTracer(tp trace.TracerProvider) trace.Tracer {
	return tp.Tracer(tracerName, trace.WithInstrumentationVersion(tracerVersion))
}

func NewClient(client *fasthttp.Client) *WrappedClient {
	return &WrappedClient{client: client}
}

type WrappedClient struct {
	client *fasthttp.Client
}

func (c *WrappedClient) DoTimeout(ctx context.Context, req *fasthttp.Request, resp *fasthttp.Response,
	timeout time.Duration,
) error {
	span := c.startSpan(ctx, req)
	err := c.client.DoTimeout(req, resp, timeout)
	span.Finish(err, resp)

	return err
}

type spanFinisher interface {
	Finish(err error, resp *fasthttp.Response)
}

type dummyFinisher struct{}

func (s dummyFinisher) Finish(error, *fasthttp.Response) {}

type spanFinisherImpl struct {
	span trace.Span
}

func (s spanFinisherImpl) Finish(err error, resp *fasthttp.Response) {
	defer s.span.End()

	if err != nil {
		s.span.RecordError(err)
		s.span.SetStatus(codes.Error, err.Error())

		return
	}

	statusCode := resp.StatusCode()

	s.span.SetAttributes(semconv.HTTPAttributesFromHTTPStatusCode(statusCode)...)
	s.span.SetStatus(semconv.SpanStatusFromHTTPStatusCode(statusCode))
}

func (c *WrappedClient) startSpan(ctx context.Context, req *fasthttp.Request) spanFinisher {
	var tracer trace.Tracer

	if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		tracer = newTracer(span.TracerProvider())
	} else {
		tracer = newTracer(otel.GetTracerProvider())
	}

	httpReq, err := toHTTPRequest(req)
	if err != nil {
		return dummyFinisher{}
	}

	operationName := fmt.Sprintf("%s %s", string(req.Host()), string(req.URI().Path()))
	ctx, span := tracer.Start(ctx, operationName,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.HTTPClientAttributesFromHTTPRequest(httpReq)...))
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(httpReq.Header))

	return spanFinisherImpl{
		span: span,
	}
}

func toHTTPRequest(req *fasthttp.Request) (*http.Request, error) {
	rURL, err := url.ParseRequestURI(string(req.RequestURI()))
	if err != nil {
		return nil, err
	}

	body := req.Body()
	r := &http.Request{}

	r.Method = string(req.Header.Method())
	r.Proto = "HTTP/1.1"
	r.ProtoMajor = 1
	r.ProtoMinor = 1
	r.ContentLength = int64(len(body))
	r.Host = string(req.URI().Host())
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.URL = rURL
	r.Header = make(http.Header)

	req.Header.VisitAll(func(k, v []byte) {
		sk := string(k)
		sv := string(v)

		switch sk {
		case "Transfer-Encoding":
			r.TransferEncoding = append(r.TransferEncoding, sv)
		default:
			r.Header.Set(sk, sv)
		}
	})

	return r, nil
}
