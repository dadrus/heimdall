// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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

package otel

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/opentelemetry/exporters"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

type mockLifecycle struct{ mock.Mock }

func (m *mockLifecycle) Append(hook fx.Hook) { m.Called(hook) }

func TestInitTraceProvider(t *testing.T) {
	for _, tc := range []struct {
		uc         string
		conf       config.TracingConfig
		setupMocks func(t *testing.T, lcMock *mockLifecycle)
		assert     func(t *testing.T, err error, propagator propagation.TextMapPropagator, logged string)
	}{
		{
			uc:   "disabled tracing",
			conf: config.TracingConfig{Enabled: false},
			assert: func(t *testing.T, err error, _ propagation.TextMapPropagator, logged string) {
				t.Helper()

				require.NoError(t, err)
				assert.Contains(t, logged, "tracing disabled")
			},
		},
		{
			uc:   "failing exporter creation",
			conf: config.TracingConfig{Enabled: true},
			setupMocks: func(t *testing.T, _ *mockLifecycle) {
				t.Helper()

				// instana exporter fails if further env vars are missing
				t.Setenv("OTEL_TRACES_EXPORTER", "instana")
			},
			assert: func(t *testing.T, err error, _ propagation.TextMapPropagator, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, exporters.ErrFailedCreatingTracesExporter)
			},
		},
		{
			uc:   "successful initialization",
			conf: config.TracingConfig{Enabled: true},
			setupMocks: func(t *testing.T, lcMock *mockLifecycle) {
				t.Helper()

				lcMock.On("Append",
					mock.MatchedBy(func(hook fx.Hook) bool {
						return hook.OnStop(context.Background()) == nil
					}),
				)
			},
			assert: func(t *testing.T, err error, propagator propagation.TextMapPropagator, logged string) {
				t.Helper()

				require.NoError(t, err)
				assert.Contains(t, logged, "tracing initialized")

				// since no OTEL environment variables are set, default propagators shall have been registered
				require.Len(t, propagator, 2)
				assert.Contains(t, propagator, propagation.TraceContext{})
				assert.Contains(t, propagator, propagation.Baggage{})
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			setupMocks := x.IfThenElse(
				tc.setupMocks != nil,
				tc.setupMocks,
				func(t *testing.T, _ *mockLifecycle) { t.Helper() })
			mock := &mockLifecycle{}
			tb := &testsupport.TestingLog{TB: t} // Capture TB log buffer.
			logger := zerolog.New(zerolog.TestWriter{T: tb})

			setupMocks(t, mock)

			// WHEN
			err := initTraceProvider(
				&config.Configuration{Tracing: tc.conf},
				resource.Default(),
				logger,
				mock,
			)
			propagator := otel.GetTextMapPropagator()

			// THEN
			tc.assert(t, err, propagator, tb.CollectedLog())
			mock.AssertExpectations(t)
		})
	}
}
