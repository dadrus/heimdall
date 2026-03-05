package rules

import (
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/dadrus/heimdall/internal/otel/semconv"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

type telemetryRule struct {
	r     rule.Rule
	t     trace.Tracer
	rd    semconv.RuleExecutionDuration
	attrs attribute.Set
}

func newTelemetryRule(rul rule.Rule, meter metric.Meter, tracer trace.Tracer) rule.Rule {
	rd, _ := semconv.NewRuleExecutionDuration(meter)

	return &telemetryRule{
		r:  rul,
		t:  tracer,
		rd: rd,
		attrs: attribute.NewSet(
			rd.AttrRuleID(rul.ID()),
			rd.AttrRuleSet(rul.SrcID()),
		),
	}
}

func (tr *telemetryRule) ID() string                   { return tr.r.ID() }
func (tr *telemetryRule) SrcID() string                { return tr.r.SrcID() }
func (tr *telemetryRule) Routes() []rule.Route         { return tr.r.Routes() }
func (tr *telemetryRule) SameAs(other rule.Rule) bool  { return tr.r.SameAs(other) }
func (tr *telemetryRule) EqualTo(other rule.Rule) bool { return tr.r.EqualTo(other) }

func (tr *telemetryRule) Execute(hctx pipeline.Context) (pipeline.Backend, error) {
	startTime := time.Now()
	ctx := hctx.Context()

	ctx, span := tr.t.Start(
		ctx,
		"Rule Execution",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			semconv.RuleIDKey.String(tr.r.ID()),
			semconv.RuleSetKey.String(tr.r.SrcID()),
		),
	)

	defer span.End()

	be, err := tr.r.Execute(hctx.WithParent(ctx))
	elapsedTime := float64(time.Since(startTime)) / float64(time.Millisecond)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	tr.rd.Record(ctx, elapsedTime, tr.attrs)

	return be, err
}
