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

package exporters

import (
	"testing"

	instana "github.com/instana/go-otel-exporter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/zipkin"
	"go.opentelemetry.io/otel/sdk/trace"

	"github.com/dadrus/heimdall/internal/x"
)

func TestCreateSpanExporters(t *testing.T) {
	for uc, tc := range map[string]struct {
		names  []string
		setup  func(t *testing.T)
		assert func(t *testing.T, err error, expts []trace.SpanExporter)
	}{
		"none exporter is at the beginning of the list": {
			names: []string{"none", "foobar"},
			assert: func(t *testing.T, err error, expts []trace.SpanExporter) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, expts, 1)
				assert.IsType(t, noopSpanExporter{}, expts[0])
			},
		},
		"none exporter is not at the beginning of the list": {
			names: []string{"zipkin", "none", "jaeger"},
			assert: func(t *testing.T, err error, expts []trace.SpanExporter) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, expts, 1)
				assert.IsType(t, noopSpanExporter{}, expts[0])
			},
		},
		"list contains unsupported exporter type": {
			names: []string{"zipkin", "foobar"},
			assert: func(t *testing.T, err error, _ []trace.SpanExporter) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedTracesExporterType)
				require.ErrorContains(t, err, "foobar")
			},
		},
		"fails creating exporter type": {
			names: []string{"instana"},
			assert: func(t *testing.T, err error, _ []trace.SpanExporter) {
				t.Helper()

				// instana exporter requires INSTANA_ENDPOINT_URL and INSTANA_AGENT_KEY
				// to be set otherwise it panics (which is recovered)

				require.Error(t, err)
				require.ErrorIs(t, err, ErrFailedCreatingTracesExporter)
				require.ErrorContains(t, err, "instana")
				require.ErrorIs(t, err, ErrFailedCreatingInstanaExporter)
				require.ErrorContains(t, err, "environment variable")
			},
		},
		"default exporter type with error": {
			setup: func(t *testing.T) {
				t.Helper()
				t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "foobar")
			},
			assert: func(t *testing.T, err error, _ []trace.SpanExporter) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedOTLPProtocol)
				require.ErrorContains(t, err, "foobar")
			},
		},
		"default exporter type": {
			assert: func(t *testing.T, err error, expts []trace.SpanExporter) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, expts, 1)
				assert.IsType(t, &otlptrace.Exporter{}, expts[0])
			},
		},
		"all supported exporter types": {
			names: []string{"otlp", "zipkin", "instana"},
			setup: func(t *testing.T) {
				t.Helper()
				t.Setenv("INSTANA_ENDPOINT_URL", "http://instana:1234")
				t.Setenv("INSTANA_AGENT_KEY", "foobar")
				t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
			},
			assert: func(t *testing.T, err error, expts []trace.SpanExporter) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, expts, 3)
				assert.IsType(t, &otlptrace.Exporter{}, expts[0])
				assert.IsType(t, &zipkin.Exporter{}, expts[1])
				assert.IsType(t, &instana.Exporter{}, expts[2])
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			setup := x.IfThenElse(tc.setup == nil, func(t *testing.T) { t.Helper() }, tc.setup)
			setup(t)

			// WHEN
			expts, err := createSpanExporters(t.Context(), tc.names...)

			// THEN
			tc.assert(t, err, expts)
		})
	}
}
