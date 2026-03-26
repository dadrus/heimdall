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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/pipeline/mocks"
)

func TestTelemetryStepID(t *testing.T) {
	t.Parallel()

	// GIVEN
	sm := mocks.NewStepMock(t)
	sm.EXPECT().ID().Return("test id")

	ts := newTelemetryStep(sm, noop.Tracer{})
	require.NotNil(t, ts)

	// WHEN & THEN
	assert.Equal(t, "test id", ts.ID())
}

func TestTelemetryStepType(t *testing.T) {
	t.Parallel()

	// GIVEN
	sm := mocks.NewStepMock(t)
	sm.EXPECT().Type().Return("test type")

	ts := newTelemetryStep(sm, noop.Tracer{})
	require.NotNil(t, ts)

	// WHEN & THEN
	assert.Equal(t, "test type", ts.Type())
}

func TestTelemetryStepKind(t *testing.T) {
	t.Parallel()

	// GIVEN
	sm := mocks.NewStepMock(t)
	sm.EXPECT().Kind().Return(pipeline.KindAuthenticator)

	ts := newTelemetryStep(sm, noop.Tracer{})
	require.NotNil(t, ts)

	// WHEN & THEN
	assert.Equal(t, pipeline.KindAuthenticator, ts.Kind())
}

func TestTelemetryStepAccept(t *testing.T) {
	t.Parallel()

	// GIVEN
	vm := mocks.NewVisitorMock(t)

	sm := mocks.NewStepMock(t)
	sm.EXPECT().Accept(vm)

	ts := newTelemetryStep(sm, noop.Tracer{})
	require.NotNil(t, ts)

	// WHEN & THEN
	ts.Accept(vm)
}

func TestTelemetryStepExecute(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]error{
		"executed without error": nil,
		"executed with error":    errors.New("test error"),
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			cm := mocks.NewContextMock(t)
			cm.EXPECT().Context().Return(t.Context())
			cm.EXPECT().WithParent(mock.Anything).Return(cm)

			sm := mocks.NewStepMock(t)
			sm.EXPECT().ID().Return("test id")
			sm.EXPECT().Type().Return("test type")
			sm.EXPECT().Kind().Return(pipeline.KindAuthenticator)
			sm.EXPECT().Execute(mock.Anything, mock.Anything).Return(tc)

			sr := tracetest.NewSpanRecorder()
			tracer := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr)).
				Tracer("test")

			ts := newTelemetryStep(sm, tracer)
			require.NotNil(t, ts)

			// WHEN
			err := ts.Execute(cm, nil)

			// THEN
			spans := sr.Ended()
			require.Len(t, spans, 1)

			span := spans[0]
			assert.Equal(t, "Step Execution", span.Name())

			if tc != nil {
				require.ErrorIs(t, tc, err)
				assert.Equal(t, codes.Error, span.Status().Code)
				assert.Equal(t, err.Error(), span.Status().Description)

				event := span.Events()
				require.Len(t, event, 1)
				assert.Equal(t, "exception", event[0].Name)

				attrs := event[0].Attributes
				require.Len(t, attrs, 2)

				assert.Contains(t, attrs, semconv.ExceptionMessage(err.Error()))
			} else {
				require.NoError(t, err)
				assert.Equal(t, codes.Unset, span.Status().Code)
				assert.Empty(t, span.Events())
			}

			attrs := span.Attributes()
			require.Len(t, attrs, 3)

			require.Contains(t, attrs, stepIDKey.String("test id"))
			require.Contains(t, attrs, mechanismKindKey.String(string(pipeline.KindAuthenticator)))
			require.Contains(t, attrs, mechanismNameKey.String("test type"))
		})
	}
}
