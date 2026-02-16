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
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

const (
	attrRuleID  = attribute.Key("rule.id")
	attrRuleSrc = attribute.Key("rule.src")
)

type ruleExecutor struct {
	r rule.Repository
	t trace.Tracer
}

func newRuleExecutor(repository rule.Repository) rule.Executor {
	tp := otel.GetTracerProvider()

	return &ruleExecutor{
		r: repository,
		t: tp.Tracer("github.com/dadrus/heimdall"),
	}
}

func (e *ruleExecutor) Execute(hctx heimdall.Context) (rule.Backend, error) {
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

	var span trace.Span

	ctx, span = e.t.Start(
		ctx,
		"Rule Execution",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attrRuleID.String(rul.ID()),
			attrRuleSrc.String(rul.SrcID()),
		),
	)

	defer span.End()

	be, err := rul.Execute(hctx.WithParent(ctx))
	if err != nil {
		span.RecordError(err)
	}

	return be, err
}
