package tracecontext

import (
	"context"

	trace2 "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

type TraceContext struct {
	TraceID  string
	SpanID   string
	ParentID string
}

func Extract(ctx context.Context) *TraceContext {
	span := trace.SpanFromContext(ctx)
	spanCtx := span.SpanContext()

	if spanCtx.IsValid() {
		ctxInfo := &TraceContext{}

		if roSpan, ok := span.(trace2.ReadOnlySpan); ok && roSpan.Parent().IsValid() {
			ctxInfo.ParentID = roSpan.Parent().SpanID().String()
		}

		ctxInfo.TraceID = spanCtx.TraceID().String()
		ctxInfo.SpanID = spanCtx.SpanID().String()

		return ctxInfo
	}

	return nil
}
