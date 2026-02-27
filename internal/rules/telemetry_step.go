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
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/dadrus/heimdall/internal/otel/semconv"
	"github.com/dadrus/heimdall/internal/pipeline"
)

type telemetryStep struct {
	s pipeline.Step
	t trace.Tracer
}

func newTelemetryStep(s pipeline.Step, t trace.Tracer) pipeline.Step {
	return &telemetryStep{s: s, t: t}
}

func (s *telemetryStep) Execute(hctx pipeline.Context, sub pipeline.Subject) error {
	ctx, span := s.t.Start(
		hctx.Context(),
		"Step Execution",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			semconv.StepID(s.ID()),
			semconv.MechanismKind(string(s.Kind())),
			semconv.MechanismName(s.Type()),
		),
	)

	defer span.End()

	err := s.s.Execute(hctx.WithParent(ctx), sub)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	return err
}

func (s *telemetryStep) ID() string                      { return s.s.ID() }
func (s *telemetryStep) Type() string                    { return s.s.Type() }
func (s *telemetryStep) Kind() pipeline.MechanismKind    { return s.s.Kind() }
func (s *telemetryStep) Accept(visitor pipeline.Visitor) { s.s.Accept(visitor) }
