package rules

import (
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

type telemetryRule struct {
	r     rule.Rule
	t     trace.Tracer
	rd    metric.Float64Histogram
	attrs attribute.Set
}

func newTelemetryRule(rul rule.Rule, meter metric.Meter, tracer trace.Tracer) (rule.Rule, error) {
	histogram, err := meter.Float64Histogram("rule.execution.duration",
		metric.WithDescription("Duration of rule executions"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(
			0.00001, 0.00005, // 10, 50µs
			0.0001, 0.00025, 0.0005, 0.00075, // 100, 250, 500, 750µs
			0.001, 0.0025, 0.005, 0.0075, // 1, 2.5, 5, 7.5ms
			0.01, 0.025, 0.05, 0.075, // 10, 25, 50, 75ms
			0.1, 0.25, 0.5, 0.75, // 100, 250, 500 750 ms
			1.0, 2.0, 5.0, // 1, 2, 5
		),
	)
	if err != nil {
		return nil, err
	}

	src := rul.Source()

	return &telemetryRule{
		r:  rul,
		t:  tracer,
		rd: histogram,
		attrs: attribute.NewSet(
			ruleIDKey.String(rul.ID()),
			ruleSetIDKey.String(src.ID),
			ruleSetNameKey.String(src.Name),
			ruleSetProviderKey.String(src.Provider),
		),
	}, nil
}

func (tr *telemetryRule) ID() string                  { return tr.r.ID() }
func (tr *telemetryRule) Source() rule.RuleSet        { return tr.r.Source() }
func (tr *telemetryRule) Routes() []rule.Route        { return tr.r.Routes() }
func (tr *telemetryRule) SameAs(other rule.Rule) bool { return tr.r.SameAs(other) }
func (tr *telemetryRule) Equals(other rule.Rule) bool { return tr.r.Equals(other) }

func (tr *telemetryRule) Execute(hctx pipeline.Context) (pipeline.Backend, error) {
	startTime := time.Now()
	ctx := hctx.Context()

	ctx, span := tr.t.Start(
		ctx,
		"Rule Execution",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(tr.attrs.ToSlice()...),
	)

	defer span.End()

	be, err := tr.r.Execute(hctx.WithParent(ctx))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	if tr.rd.Enabled(ctx) {
		elapsedTime := float64(time.Since(startTime)) / float64(time.Millisecond)

		tr.rd.Record(ctx, elapsedTime, metric.WithAttributeSet(tr.attrs))
	}

	return be, err
}
