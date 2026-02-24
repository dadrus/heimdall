// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/dadrus/heimdall/internal/otel/semconv"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

type ruleExecutor struct {
	r  rule.Repository
	t  trace.Tracer
	rd semconv.RuleExecutionDuration
}

func newRuleExecutor(repository rule.Repository, meter metric.Meter, tracer trace.Tracer) pipeline.Executor {
	rd, _ := semconv.NewRuleExecutionDuration(meter)

	return &ruleExecutor{
		r:  repository,
		t:  tracer,
		rd: rd,
	}
}

func (e *ruleExecutor) Execute(hctx pipeline.Context) (pipeline.Backend, error) {
	startTime := time.Now()
	request := hctx.Request()
	ctx := hctx.Context()

	zerolog.Ctx(ctx).Debug().
		Str("_method", request.Method).
		Str("_url", request.URL.String()).
		Msg("Analyzing request")

	rul, err := e.r.FindRule(hctx)
	if err != nil {
		return nil, err
	}

	ctx, span := e.t.Start(
		ctx,
		"Rule Execution",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			semconv.RuleIDKey.String(rul.ID()),
			semconv.RuleSetKey.String(rul.SrcID()),
		),
	)

	defer span.End()

	be, err := rul.Execute(hctx.WithParent(ctx))
	elapsedTime := float64(time.Since(startTime)) / float64(time.Millisecond)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	e.rd.Record(ctx, elapsedTime, attribute.NewSet(
		e.rd.AttrRuleID(rul.ID()),
		e.rd.AttrRuleSet(rul.SrcID()),
	))

	return be, err
}
