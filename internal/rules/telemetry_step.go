package rules

import (
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/identity"
)

const (
	attrStepID        = attribute.Key("step.id")
	attrStepError     = attribute.Key("step.error")
	attrMechanismType = attribute.Key("mechanism.type")
	attrMechanismKind = attribute.Key("mechanism.kind")
)

type telemetryStep struct {
	s    heimdall.Step
	typ  string
	kind string
}

func (s *telemetryStep) Accept(visitor heimdall.Visitor) { s.s.Accept(visitor) }

func (s *telemetryStep) ID() string { return s.s.ID() }

func (s *telemetryStep) Execute(ctx heimdall.Context, sub identity.Subject) error {
	var kvs [4]attribute.KeyValue

	span := trace.SpanFromContext(ctx.Context())

	attrs := append(kvs[:0],
		attrStepID.String(s.s.ID()),
		attrMechanismKind.String(s.kind),
		attrMechanismType.String(s.typ),
	)

	span.AddEvent("step started",
		trace.WithTimestamp(time.Now()),
		trace.WithAttributes(attrs...),
	)

	err := s.s.Execute(ctx, sub)
	if err != nil {
		attrs = append(attrs, attrStepError.String(err.Error()))
	}

	span.AddEvent("step completed",
		trace.WithTimestamp(time.Now()),
		trace.WithAttributes(attrs...),
	)

	return err
}
