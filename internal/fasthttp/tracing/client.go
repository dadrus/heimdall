package tracing

import (
	"context"
	"net/http"
	"time"

	"github.com/dadrus/heimdall/internal/x"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/valyala/fasthttp"
)

func NewClient(client *fasthttp.Client, tracer opentracing.Tracer) *WrappedClient {
	return &WrappedClient{tracer: tracer, client: client}
}

type WrappedClient struct {
	tracer opentracing.Tracer
	client *fasthttp.Client
}

func (c *WrappedClient) DoTimeout(ctx context.Context, req *fasthttp.Request, resp *fasthttp.Response, timeout time.Duration) error {
	span := c.startSpan(ctx, req)
	err := c.client.DoTimeout(req, resp, timeout)
	span.finish(x.IfThenElse(err == nil, resp, nil))

	return err
}

func (c *WrappedClient) DoDeadline(ctx context.Context, req *fasthttp.Request, resp *fasthttp.Response, deadline time.Time) error {
	span := c.startSpan(ctx, req)
	err := c.client.DoDeadline(req, resp, deadline)
	span.finish(x.IfThenElse(err == nil, resp, nil))

	return err
}

func (c *WrappedClient) DoRedirects(ctx context.Context, req *fasthttp.Request, resp *fasthttp.Response, maxRedirectsCount int) error {
	span := c.startSpan(ctx, req)
	err := c.client.DoRedirects(req, resp, maxRedirectsCount)
	span.finish(x.IfThenElse(err == nil, resp, nil))

	return err
}

func (c *WrappedClient) Do(ctx context.Context, req *fasthttp.Request, resp *fasthttp.Response) error {
	span := c.startSpan(ctx, req)
	err := c.client.Do(req, resp)
	span.finish(x.IfThenElse(err == nil, resp, nil))

	return err
}

func spanContext(ctx context.Context) opentracing.SpanContext {
	parent := opentracing.SpanFromContext(ctx)

	if parent != nil {
		return parent.Context()
	}

	return nil
}

type spanFinisher struct {
	root opentracing.Span
	sp   opentracing.Span
}

func (s spanFinisher) finish(resp *fasthttp.Response) {
	defer s.sp.Finish()
	defer s.root.Finish()

	if resp == nil {
		return
	}

	statusCode := resp.StatusCode()

	ext.HTTPStatusCode.Set(s.sp, uint16(statusCode))
	if statusCode >= http.StatusInternalServerError {
		ext.Error.Set(s.sp, true)
	}
}

func (c *WrappedClient) startSpan(ctx context.Context, req *fasthttp.Request) spanFinisher {
	method := string(req.Header.Method())

	root := c.tracer.StartSpan("HTTP Client", opentracing.ChildOf(spanContext(ctx)))
	span := c.tracer.StartSpan("HTTP "+string(req.Header.Method()), opentracing.ChildOf(root.Context()))

	ext.SpanKindRPCClient.Set(span)
	ext.Component.Set(span, "net/http")
	ext.HTTPMethod.Set(span, method)
	ext.HTTPUrl.Set(span, req.URI().String())

	headers := make(opentracing.HTTPHeadersCarrier)
	req.Header.VisitAll(func(key, value []byte) { headers.Set(string(key), string(value)) })

	span.Tracer().Inject(span.Context(), opentracing.HTTPHeaders, headers)

	return spanFinisher{
		root: root,
		sp:   span,
	}
}
