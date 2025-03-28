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

package exporters

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"

	"github.com/dadrus/heimdall/internal/x"
)

func TestCreateMetricReaders(t *testing.T) {
	for uc, tc := range map[string]struct {
		names  []string
		setup  func(t *testing.T)
		assert func(t *testing.T, err error, readers []metric.Reader)
	}{
		"none exporter is at the beginning of the list": {
			names: []string{"none", "foobar"},
			assert: func(t *testing.T, err error, readers []metric.Reader) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, readers, 1)
				assert.IsType(t, &metric.PeriodicReader{}, readers[0])
			},
		},
		"none exporter is not at the beginning of the list": {
			names: []string{"otlp", "none", "prometheus"},
			assert: func(t *testing.T, err error, readers []metric.Reader) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, readers, 1)
				assert.IsType(t, &metric.PeriodicReader{}, readers[0])
			},
		},
		"list contains unsupported exporter type": {
			names: []string{"otlp", "foobar"},
			assert: func(t *testing.T, err error, _ []metric.Reader) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedMetricExporterType)
				assert.Contains(t, err.Error(), "foobar")
			},
		},
		"fails creating exporter type": {
			names: []string{"otlp"},
			setup: func(t *testing.T) {
				t.Helper()

				t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "foobar")
			},
			assert: func(t *testing.T, err error, _ []metric.Reader) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrFailedCreatingMetricExporter)
				assert.Contains(t, err.Error(), "otlp")
				require.ErrorIs(t, err, ErrUnsupportedOTLPProtocol)
				assert.Contains(t, err.Error(), "foobar")
			},
		},
		"default exporter type with error": {
			setup: func(t *testing.T) {
				t.Helper()
				t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "foobar")
			},
			assert: func(t *testing.T, err error, _ []metric.Reader) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedOTLPProtocol)
				assert.Contains(t, err.Error(), "foobar")
			},
		},
		"default exporter type": {
			assert: func(t *testing.T, err error, readers []metric.Reader) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, readers, 1)
				assert.IsType(t, &metric.PeriodicReader{}, readers[0])
			},
		},
		"all supported exporter types": {
			names: []string{"otlp", "prometheus"},
			setup: func(t *testing.T) {
				t.Helper()

				t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
			},
			assert: func(t *testing.T, err error, readers []metric.Reader) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, readers, 2)
				assert.IsType(t, &metric.PeriodicReader{}, readers[0])
				assert.IsType(t, &prometheus.Exporter{}, readers[1])
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			setup := x.IfThenElse(tc.setup == nil, func(t *testing.T) { t.Helper() }, tc.setup)
			setup(t)

			// WHEN
			readers, err := createMetricsReaders(t.Context(), tc.names...)

			// THEN
			tc.assert(t, err, readers)
		})
	}
}
