// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/dadrus/heimdall/internal/x/stringx"
)

const (
	tracerName    = "github.com/dadrus/heimdall/internal/fasthttp/middleware/opentelemetry"
	tracerVersion = "semver:0.1.0"
)

type fasthttpHeaderCarrier struct {
	header *fasthttp.RequestHeader
}

func (c *fasthttpHeaderCarrier) Get(key string) string { return stringx.ToString(c.header.Peek(key)) }

func (c *fasthttpHeaderCarrier) Set(key string, value string) { c.header.Set(key, value) }

func (c *fasthttpHeaderCarrier) Keys() []string {
	var headerNames []string

	c.header.VisitAll(func(key, value []byte) {
		headerNames = append(headerNames, stringx.ToString(key))
	})

	return headerNames
}

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

	operationName := fmt.Sprintf("%s %s %s @%s",
		stringx.ToString(req.Header.Protocol()),
		stringx.ToString(req.Header.Method()),
		stringx.ToString(req.URI().Path()),
		stringx.ToString(req.Host()))
	ctx, span := tracer.Start(ctx, operationName,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.HTTPClientAttributesFromHTTPRequest(httpReq)...))

	otel.GetTextMapPropagator().Inject(ctx, &fasthttpHeaderCarrier{header: &req.Header})

	return spanFinisherImpl{
		span: span,
	}
}

func toHTTPRequest(req *fasthttp.Request) (*http.Request, error) {
	rURL, err := url.ParseRequestURI(stringx.ToString(req.RequestURI()))
	if err != nil {
		return nil, err
	}

	body := req.Body()
	r := &http.Request{}

	r.Method = stringx.ToString(req.Header.Method())
	r.Proto = "HTTP/1.1"
	r.ProtoMajor = 1
	r.ProtoMinor = 1
	r.ContentLength = int64(len(body))
	r.Host = stringx.ToString(req.URI().Host())
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.URL = rURL
	r.Header = make(http.Header)

	req.Header.VisitAll(func(k, v []byte) {
		sk := stringx.ToString(k)
		sv := stringx.ToString(v)

		switch sk {
		case "Transfer-Encoding":
			r.TransferEncoding = append(r.TransferEncoding, sv)
		default:
			r.Header.Set(sk, sv)
		}
	})

	return r, nil
}
