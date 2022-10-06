package opentelemetry

import (
	"github.com/gofiber/fiber/v2"
	"go.opentelemetry.io/otel/trace"
)

type (
	SpanObserver          func(*fiber.Ctx, trace.Span)
	OperationNameProvider func(*fiber.Ctx) string
	OperationFilter       func(*fiber.Ctx) bool
)

type opts struct {
	tracer                 trace.Tracer
	spanObserver           SpanObserver
	operationName          OperationNameProvider
	filterOperation        OperationFilter
	skipSpansWithoutParent bool
}

type Option func(*opts)

func WithTracer(tracer trace.Tracer) Option {
	return func(o *opts) {
		if tracer != nil {
			o.tracer = tracer
		}
	}
}

func WithSpanObserver(observer SpanObserver) Option {
	return func(o *opts) {
		if observer != nil {
			o.spanObserver = observer
		}
	}
}

func WithOperationNameProvider(provider OperationNameProvider) Option {
	return func(o *opts) {
		if provider != nil {
			o.operationName = provider
		}
	}
}

func WithOperationFilter(filter OperationFilter) Option {
	return func(o *opts) {
		if filter != nil {
			o.filterOperation = filter
		}
	}
}

func WithSkipSpanWithoutParent(flag bool) Option {
	return func(o *opts) {
		o.skipSpansWithoutParent = flag
	}
}
