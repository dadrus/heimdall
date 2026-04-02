// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package rules

import (
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	noopmetric "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	nooptrace "go.opentelemetry.io/otel/trace/noop"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type executorFunc func(ctx pipeline.Context) (pipeline.Backend, error)

type telemetryRule struct {
	r  rule.Rule
	do executorFunc
}

func newTelemetryRule(rul rule.Rule, meter metric.Meter, tracer trace.Tracer) (rule.Rule, error) {
	src := rul.Source()
	attrs := []attribute.KeyValue{
		ruleIDKey.String(rul.ID()),
		ruleSetIDKey.String(src.ID),
		ruleSetNameKey.String(src.Name),
		ruleSetProviderKey.String(src.Provider),
	}

	exec, err := decorateWithMeter(rul.Execute, meter, attrs)
	if err != nil {
		return nil, err
	}

	return &telemetryRule{
		r:  rul,
		do: decorateWithTracer(exec, tracer, attrs),
	}, nil
}

func decorateWithTracer(exec executorFunc, tracer trace.Tracer, attrs []attribute.KeyValue) executorFunc {
	if _, isNoopTracer := tracer.(nooptrace.Tracer); isNoopTracer {
		return exec
	}

	return func(hctx pipeline.Context) (pipeline.Backend, error) {
		ctx := hctx.Context()
		ctx, span := tracer.Start(
			ctx,
			"Rule Execution",
			trace.WithSpanKind(trace.SpanKindInternal),
			trace.WithAttributes(attrs...),
		)

		be, err := exec(hctx.WithParent(ctx))
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}

		span.End()

		return be, err
	}
}

func decorateWithMeter(exec executorFunc, meter metric.Meter, attrs []attribute.KeyValue) (executorFunc, error) {
	if _, isNoopMeter := meter.(noopmetric.Meter); isNoopMeter {
		return exec, nil
	}

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
		return nil, errorchain.NewWithMessagef(pipeline.ErrInternal,
			"failed creating rule.execution.duration histogram").CausedBy(err)
	}

	attrSet := attribute.NewSet(attrs...)

	return func(ctx pipeline.Context) (pipeline.Backend, error) {
		startTime := time.Now()

		be, err := exec(ctx)

		histogram.Record(
			ctx.Context(),
			time.Since(startTime).Seconds(),
			metric.WithAttributeSet(attrSet),
		)

		return be, err
	}, nil
}

func (tr *telemetryRule) ID() string                                              { return tr.r.ID() }
func (tr *telemetryRule) Source() rule.RuleSet                                    { return tr.r.Source() }
func (tr *telemetryRule) Routes() []rule.Route                                    { return tr.r.Routes() }
func (tr *telemetryRule) SameAs(other rule.Rule) bool                             { return tr.r.SameAs(other) }
func (tr *telemetryRule) Equals(other rule.Rule) bool                             { return tr.r.Equals(other) }
func (tr *telemetryRule) Execute(hctx pipeline.Context) (pipeline.Backend, error) { return tr.do(hctx) }
