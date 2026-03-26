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
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
	oteltrace "go.opentelemetry.io/otel/trace"
	nooptrace "go.opentelemetry.io/otel/trace/noop"

	"github.com/dadrus/heimdall/internal/pipeline/mocks"
	"github.com/dadrus/heimdall/internal/rules/rule"
	mocks2 "github.com/dadrus/heimdall/internal/rules/rule/mocks"
	"github.com/dadrus/heimdall/internal/x"
)

func TestTelemetryRuleID(t *testing.T) {
	t.Parallel()

	// GIVEN
	rm := mocks2.NewRuleMock(t)
	rm.EXPECT().ID().Return("test rule id")
	rm.EXPECT().Source().Return(rule.RuleSet{})

	tr, err := newTelemetryRule(rm, noop.Meter{}, nooptrace.Tracer{})
	require.NoError(t, err)
	require.NotNil(t, tr)

	// WHEN & THEN
	assert.Equal(t, "test rule id", tr.ID())
}

func TestTelemetryRuleSource(t *testing.T) {
	t.Parallel()

	// GIVEN
	src := rule.RuleSet{ID: "test-id", Name: "test-name", Provider: "test-provider"}

	rm := mocks2.NewRuleMock(t)
	rm.EXPECT().ID().Return("test rule id")
	rm.EXPECT().Source().Return(src)

	tr, err := newTelemetryRule(rm, noop.Meter{}, nooptrace.Tracer{})
	require.NoError(t, err)
	require.NotNil(t, tr)

	// WHEN & THEN
	assert.Equal(t, src, tr.Source())
}

func TestTelemetryRuleRoutes(t *testing.T) {
	t.Parallel()

	// GIVEN
	rm := mocks2.NewRuleMock(t)
	rm.EXPECT().ID().Return("test rule id")
	rm.EXPECT().Source().Return(rule.RuleSet{})
	rm.EXPECT().Routes().Return(nil)

	tr, err := newTelemetryRule(rm, noop.Meter{}, nooptrace.Tracer{})
	require.NoError(t, err)
	require.NotNil(t, tr)

	// WHEN & THEN
	tr.Routes()
}

func TestTelemetryRuleSameAs(t *testing.T) {
	t.Parallel()

	// GIVEN
	other := mocks2.NewRuleMock(t)

	rm := mocks2.NewRuleMock(t)
	rm.EXPECT().ID().Return("test rule id")
	rm.EXPECT().Source().Return(rule.RuleSet{})
	rm.EXPECT().SameAs(other).Return(true)

	tr, err := newTelemetryRule(rm, noop.Meter{}, nooptrace.Tracer{})
	require.NoError(t, err)
	require.NotNil(t, tr)

	// WHEN & THEN
	assert.True(t, tr.SameAs(other))
}

func TestTelemetryRuleEquals(t *testing.T) {
	t.Parallel()

	// GIVEN
	other := mocks2.NewRuleMock(t)

	rm := mocks2.NewRuleMock(t)
	rm.EXPECT().ID().Return("test rule id")
	rm.EXPECT().Source().Return(rule.RuleSet{})
	rm.EXPECT().Equals(other).Return(true)

	tr, err := newTelemetryRule(rm, noop.Meter{}, nooptrace.Tracer{})
	require.NoError(t, err)
	require.NotNil(t, tr)

	// WHEN & THEN
	assert.True(t, tr.Equals(other))
}

func TestTelemetryRuleExecute(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		err         error
		withMetrics bool
	}{
		"successful execution without metrics":      {},
		"successful execution with metrics enabled": {withMetrics: true},
		"executed with error and metrics enabled":   {withMetrics: true, err: errors.New("test error")},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			src := rule.RuleSet{ID: "test ruleset id", Name: "test ruleset name", Provider: "test provider"}
			bem := mocks.NewBackendMock(t)

			cm := mocks.NewContextMock(t)
			cm.EXPECT().Context().Return(t.Context())
			cm.EXPECT().WithParent(mock.MatchedBy(func(ctx context.Context) bool {
				return oteltrace.SpanFromContext(ctx).SpanContext().IsValid()
			})).Return(cm)

			rulMock := mocks2.NewRuleMock(t)
			rulMock.EXPECT().ID().Return("test rule id")
			rulMock.EXPECT().Source().Return(src)
			rulMock.EXPECT().Execute(cm).Return(bem, tc.err)

			sr := tracetest.NewSpanRecorder()
			tracer := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr)).Tracer("test")

			reader := sdkmetric.NewManualReader()

			meter := x.IfThenElse(tc.withMetrics,
				sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"),
				noop.NewMeterProvider().Meter("test"),
			)

			decorated, err := newTelemetryRule(rulMock, meter, tracer)
			require.NoError(t, err)
			require.NotNil(t, decorated)

			// WHEN
			be, err := decorated.Execute(cm)

			// THEN
			assert.Equal(t, bem, be)

			spans := sr.Ended()
			require.Len(t, spans, 1)

			span := spans[0]
			assert.Equal(t, "Rule Execution", span.Name())

			if tc.err != nil {
				require.ErrorIs(t, tc.err, err)
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

			spanAttrs := span.Attributes()
			require.Len(t, spanAttrs, 4)
			assert.Contains(t, spanAttrs, ruleIDKey.String("test rule id"))
			assert.Contains(t, spanAttrs, ruleSetIDKey.String(src.ID))
			assert.Contains(t, spanAttrs, ruleSetNameKey.String(src.Name))
			assert.Contains(t, spanAttrs, ruleSetProviderKey.String(src.Provider))

			var resourceMetrics metricdata.ResourceMetrics
			require.NoError(t, reader.Collect(t.Context(), &resourceMetrics))

			if !tc.withMetrics {
				require.Empty(t, resourceMetrics.ScopeMetrics)

				return
			}

			require.NotEmpty(t, resourceMetrics.ScopeMetrics)
			require.Len(t, resourceMetrics.ScopeMetrics[0].Metrics, 1)
			assert.Equal(t, "rule.execution.duration", resourceMetrics.ScopeMetrics[0].Metrics[0].Name)
			assert.Equal(t, "Duration of rule executions", resourceMetrics.ScopeMetrics[0].Metrics[0].Description)
			assert.Equal(t, "s", resourceMetrics.ScopeMetrics[0].Metrics[0].Unit)

			histogram, ok := resourceMetrics.ScopeMetrics[0].Metrics[0].Data.(metricdata.Histogram[float64])
			require.True(t, ok)

			dp := histogram.DataPoints
			require.Len(t, dp, 1)
			assert.Equal(t, uint64(1), dp[0].Count)
			assert.Len(t, dp[0].Exemplars, 1)
			assert.GreaterOrEqual(t, dp[0].Sum, float64(0))

			require.Equal(t, 4, dp[0].Attributes.Len())

			val, ok := dp[0].Attributes.Value(ruleIDKey)
			require.True(t, ok)
			assert.Equal(t, "test rule id", val.AsString())

			val, ok = dp[0].Attributes.Value(ruleSetIDKey)
			require.True(t, ok)
			assert.Equal(t, src.ID, val.AsString())

			val, ok = dp[0].Attributes.Value(ruleSetNameKey)
			require.True(t, ok)
			assert.Equal(t, src.Name, val.AsString())

			val, ok = dp[0].Attributes.Value(ruleSetProviderKey)
			require.True(t, ok)
			assert.Equal(t, src.Provider, val.AsString())
		})
	}
}
