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

package metrics

import (
	"context"
	"strconv"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/fxlcm"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewLifecycleManager(t *testing.T) {
	for _, tc := range []struct {
		uc     string
		setup  func(t *testing.T) *config.Configuration
		assert func(t *testing.T, lm lifecycleManager)
	}{
		{
			uc: "metrics disabled by configuration",
			setup: func(t *testing.T) *config.Configuration {
				t.Helper()

				return &config.Configuration{}
			},
			assert: func(t *testing.T, lm lifecycleManager) {
				t.Helper()

				require.IsType(t, noopManager{}, lm)
				require.NoError(t, lm.Start(context.TODO()))
				require.NoError(t, lm.Stop(context.TODO()))
			},
		},
		{
			uc: "OTEL_METRICS_EXPORTER env var contains prometheus and none",
			setup: func(t *testing.T) *config.Configuration {
				t.Helper()
				t.Setenv("OTEL_METRICS_EXPORTER", "prometheus,none")

				return &config.Configuration{Metrics: config.MetricsConfig{Enabled: true}}
			},
			assert: func(t *testing.T, lm lifecycleManager) {
				t.Helper()

				require.IsType(t, noopManager{}, lm)
				require.NoError(t, lm.Start(context.TODO()))
				require.NoError(t, lm.Stop(context.TODO()))
			},
		},
		{
			uc: "OTEL_METRICS_EXPORTER env var does not contain prometheus",
			setup: func(t *testing.T) *config.Configuration {
				t.Helper()
				t.Setenv("OTEL_METRICS_EXPORTER", "otlp")

				return &config.Configuration{Metrics: config.MetricsConfig{Enabled: true}}
			},
			assert: func(t *testing.T, lm lifecycleManager) {
				t.Helper()

				require.IsType(t, noopManager{}, lm)
				require.NoError(t, lm.Start(context.TODO()))
				require.NoError(t, lm.Stop(context.TODO()))
			},
		},
		{
			uc: "metrics enabled and OTEL_METRICS_EXPORTER env var contains prometheus",
			setup: func(t *testing.T) *config.Configuration {
				t.Helper()
				t.Setenv("OTEL_METRICS_EXPORTER", "prometheus")

				port, err := testsupport.GetFreePort()
				require.NoError(t, err)

				t.Setenv("OTEL_EXPORTER_PROMETHEUS_PORT", strconv.Itoa(port))

				return &config.Configuration{
					Metrics: config.MetricsConfig{
						Enabled: true,
					},
				}
			},
			assert: func(t *testing.T, lm lifecycleManager) {
				t.Helper()

				require.IsType(t, &fxlcm.LifecycleManager{}, lm)
				require.NoError(t, lm.Start(context.TODO()))
				require.NoError(t, lm.Stop(context.TODO()))
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			conf := tc.setup(t)

			// WHEN
			lm := newLifecycleManager(conf, log.Logger)

			// THEN
			tc.assert(t, lm)
		})
	}
}
