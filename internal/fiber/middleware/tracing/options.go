package tracing

import (
	"github.com/gofiber/fiber/v2"
	"github.com/opentracing/opentracing-go"
)

type (
	SpanTagsModifier      func(ctx *fiber.Ctx, span opentracing.Span)
	OperationNameProvider func(ctx *fiber.Ctx) string
	OperationFilter       func(*fiber.Ctx) bool
)

type opts struct {
	tracer                 opentracing.Tracer
	modifySpan             SpanTagsModifier
	operationName          OperationNameProvider
	filterOperation        OperationFilter
	skipSpansWithoutParent bool
}

type Option func(*opts)

func WithTracer(tracer opentracing.Tracer) Option {
	return func(o *opts) {
		o.tracer = tracer
	}
}

func WithSpanTagsModifier(modifier SpanTagsModifier) Option {
	return func(o *opts) {
		o.modifySpan = modifier
	}
}

func WithOperationNameProvider(provider OperationNameProvider) Option {
	return func(o *opts) {
		o.operationName = provider
	}
}

func WithOperationFiler(filter OperationFilter) Option {
	return func(o *opts) {
		o.filterOperation = filter
	}
}

func WithSkipSpanWithoutParent(flag bool) Option {
	return func(o *opts) {
		o.skipSpansWithoutParent = flag
	}
}
