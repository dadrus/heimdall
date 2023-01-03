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
	"errors"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"go.opentelemetry.io/otel/trace"
)

var ErrNoParentSpan = errors.New("no parent span available")

type tracer struct {
	c *tracerConfig
}

type tracerConfig struct {
	tracer                 trace.Tracer
	spanObserver           SpanObserver
	operationName          OperationNameProvider
	filterOperation        OperationFilter
	skipSpansWithoutParent bool
}

func newTracerConfig(opts ...Option) *tracerConfig {
	options := defaultOptions

	for _, opt := range opts {
		opt(&options)
	}

	return &tracerConfig{
		tracer:                 options.tracer,
		spanObserver:           options.spanObserver,
		operationName:          options.operationName,
		filterOperation:        options.filterOperation,
		skipSpansWithoutParent: options.skipSpansWithoutParent,
	}
}

func (t *tracer) manageSpans(ctx *fiber.Ctx) error {
	now := time.Now()

	if t.c.filterOperation(ctx) {
		return ctx.Next()
	}

	span, err := t.startSpan(ctx, now)
	if err != nil {
		return ctx.Next()
	}

	defer t.endSpan(ctx, span)

	return ctx.Next()
}

func (t *tracer) startSpan(ctx *fiber.Ctx, time time.Time) (trace.Span, error) {
	req := &http.Request{}

	err := fasthttpadaptor.ConvertRequest(ctx.Context(), req, true)
	if err != nil {
		return nil, err
	}

	spanCtx := otel.GetTextMapPropagator().Extract(ctx.UserContext(), propagation.HeaderCarrier(req.Header))

	var spanOpts []trace.SpanStartOption

	sc := trace.SpanContextFromContext(spanCtx)
	if !sc.IsValid() {
		if t.c.skipSpansWithoutParent {
			return nil, ErrNoParentSpan
		}

		spanOpts = append(spanOpts, trace.WithNewRoot())
	}

	spanOpts = append(spanOpts,
		trace.WithAttributes(semconv.NetAttributesFromHTTPRequest("tcp", req)...),
		trace.WithAttributes(semconv.EndUserAttributesFromHTTPRequest(req)...),
		trace.WithAttributes(semconv.HTTPServerAttributesFromHTTPRequest("", "", req)...),
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithTimestamp(time))

	userCtx, span := t.c.tracer.Start(spanCtx, t.c.operationName(ctx), spanOpts...)

	t.c.spanObserver(ctx, span)

	ctx.SetUserContext(userCtx)

	return span, nil
}

func (t *tracer) endSpan(ctx *fiber.Ctx, span trace.Span) {
	statusCode := ctx.Response().StatusCode()
	attributes := semconv.HTTPAttributesFromHTTPStatusCode(statusCode)

	span.SetAttributes(attributes...)
	span.SetStatus(semconv.SpanStatusFromHTTPStatusCode(statusCode))

	span.End(trace.WithTimestamp(time.Now()), trace.WithStackTrace(false))
}

func New(opts ...Option) fiber.Handler {
	trc := &tracer{c: newTracerConfig(opts...)}

	return trc.manageSpans
}
