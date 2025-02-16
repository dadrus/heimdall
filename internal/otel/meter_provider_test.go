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
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/opentelemetry/exporters"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestInitMeterProvider(t *testing.T) {
	for _, tc := range []struct {
		uc         string
		conf       config.MetricsConfig
		setupMocks func(t *testing.T, lcMock *mockLifecycle)
		assert     func(t *testing.T, err error, logged string)
	}{
		{
			uc:   "disabled tracing",
			conf: config.MetricsConfig{Enabled: false},
			assert: func(t *testing.T, err error, logged string) {
				t.Helper()

				require.NoError(t, err)
				assert.Contains(t, logged, "metrics disabled")
			},
		},
		{
			uc:   "failing exporter creation",
			conf: config.MetricsConfig{Enabled: true},
			setupMocks: func(t *testing.T, _ *mockLifecycle) {
				t.Helper()

				t.Setenv("OTEL_METRICS_EXPORTER", "does_not_exist")
			},
			assert: func(t *testing.T, err error, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, exporters.ErrUnsupportedMetricExporterType)
			},
		},
		{
			uc:   "successful initialization",
			conf: config.MetricsConfig{Enabled: true},
			setupMocks: func(t *testing.T, lcMock *mockLifecycle) {
				t.Helper()

				t.Setenv("OTEL_METRICS_EXPORTER", "none")
				lcMock.On("Append",
					mock.MatchedBy(func(hook fx.Hook) bool {
						return hook.OnStop(t.Context()) == nil
					}),
				)
			},
			assert: func(t *testing.T, err error, logged string) {
				t.Helper()

				require.NoError(t, err)
				assert.Contains(t, logged, "metrics initialized")
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
			err := initMeterProvider(
				&config.Configuration{Metrics: tc.conf},
				resource.Default(),
				logger,
				mock,
			)

			// THEN
			tc.assert(t, err, tb.CollectedLog())
			mock.AssertExpectations(t)
		})
	}
}
