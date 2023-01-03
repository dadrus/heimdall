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
	"context"
	"errors"
	"fmt"
	"testing"

	instana "github.com/instana/go-otel-exporter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/zipkin"
	"go.opentelemetry.io/otel/sdk/trace"

	"github.com/dadrus/heimdall/internal/x"
)

var ErrTest = errors.New("for test purpose")

func TestRegistryEmptyStore(t *testing.T) {
	t.Parallel()

	// GIVEN
	r := registry{}

	// WHEN
	err := r.store("first", func(ctx context.Context) (trace.SpanExporter, error) { return nil, nil })

	// THEN
	require.NoError(t, err)
}

func TestRegistryNonEmptyStore(t *testing.T) {
	t.Parallel()

	// GIVEN
	r := registry{}
	require.NoError(t, r.store("first", func(ctx context.Context) (trace.SpanExporter, error) { return nil, nil }))

	// WHEN
	err := r.store("second", func(ctx context.Context) (trace.SpanExporter, error) { return nil, nil })

	// THEN
	require.NoError(t, err)
}

func TestRegistryDuplicateStore(t *testing.T) {
	t.Parallel()

	// GIVEN
	r := registry{}
	require.NoError(t, r.store("first", func(ctx context.Context) (trace.SpanExporter, error) { return nil, nil }))

	// WHEN
	err := r.store("first", func(ctx context.Context) (trace.SpanExporter, error) { return nil, nil })

	// THEN
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDuplicateRegistration)
	assert.Contains(t, err.Error(), "first")
}

func TestRegistryEmptyLoad(t *testing.T) {
	t.Parallel()

	// GIVEN
	r := registry{}

	// WHEN
	v, ok := r.load("non-existent")

	// THEN
	assert.False(t, ok, "empty registry should hold nothing")
	assert.Nil(t, v, "non-nil executor factory returned")
}

func TestRegistryExistentLoad(t *testing.T) {
	t.Parallel()

	// GIVEN
	reg := registry{}

	require.NoError(t, reg.store("existent",
		func(ctx context.Context) (trace.SpanExporter, error) { return nil, ErrTest }))

	// WHEN
	value, ok := reg.load("existent")

	// THEN
	assert.True(t, ok, "registry should hold expected factory")
	assert.NotNil(t, value)

	_, err := value(context.Background())
	assert.Equal(t, ErrTest, err)
}

func TestRegisterSpanExporterFactory(t *testing.T) {
	t.Cleanup(func() { exporters.remove("custom") })

	// WHEN
	RegisterSpanExporterFactory("custom",
		func(ctx context.Context) (trace.SpanExporter, error) { return nil, ErrTest })

	// THEN
	v, ok := exporters.load("custom")
	assert.True(t, ok)

	_, err := v(context.Background())
	assert.Equal(t, ErrTest, err)
}

func TestDuplicateRegisterSpanExporterFactoryPanics(t *testing.T) {
	// GIVEN
	name := "custom"
	factory := func(ctx context.Context) (trace.SpanExporter, error) { return nil, ErrTest }
	errString := fmt.Sprintf("%s: %s", ErrDuplicateRegistration, name)

	t.Cleanup(func() { exporters.remove(name) })

	// GIVEN
	RegisterSpanExporterFactory(name, factory)

	// WHEN & THEN
	assert.PanicsWithError(t, errString, func() {
		RegisterSpanExporterFactory(name, factory)
	})
}

func TestCreateSpanExporters(t *testing.T) {
	for _, tc := range []struct {
		uc     string
		names  []string
		setup  func(t *testing.T)
		assert func(t *testing.T, err error, expts []trace.SpanExporter)
	}{
		{
			uc:    "none exporter is at the beginning of the list",
			names: []string{"none", "foobar"},
			assert: func(t *testing.T, err error, expts []trace.SpanExporter) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, expts, 1)
				assert.IsType(t, noopExporter{}, expts[0])
			},
		},
		{
			uc:    "none exporter is not at the beginning of the list",
			names: []string{"zipkin", "none", "jaeger"},
			assert: func(t *testing.T, err error, expts []trace.SpanExporter) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, expts, 1)
				assert.IsType(t, noopExporter{}, expts[0])
			},
		},
		{
			uc:    "list contains unsupported exporter type",
			names: []string{"zipkin", "jaeger", "foobar"},
			assert: func(t *testing.T, err error, expts []trace.SpanExporter) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrUnsupportedExporterType)
				assert.Contains(t, err.Error(), "foobar")
			},
		},
		{
			uc:    "fails creating exporter type",
			names: []string{"instana"},
			assert: func(t *testing.T, err error, expts []trace.SpanExporter) {
				t.Helper()

				// instana exporter requires INSTANA_ENDPOINT_URL and INSTANA_AGENT_KEY
				// to be set otherwise it panics (which is recovered)

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrFailedCreatingExporter)
				assert.Contains(t, err.Error(), "instana")
				assert.ErrorIs(t, err, ErrFailedCreatingInstanaExporter)
				assert.Contains(t, err.Error(), "environment variable")
			},
		},
		{
			uc: "default exporter type with error",
			setup: func(t *testing.T) {
				t.Helper()
				t.Setenv(otelExporterOtlpTracesProtocolEnvKey, "foobar")
			},
			assert: func(t *testing.T, err error, expts []trace.SpanExporter) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrUnsupportedOTLPProtocol)
				assert.Contains(t, err.Error(), "foobar")
			},
		},
		{
			uc: "default exporter type",
			assert: func(t *testing.T, err error, expts []trace.SpanExporter) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, expts, 1)
				assert.IsType(t, &otlptrace.Exporter{}, expts[0])
			},
		},
		{
			uc:    "all supported exporter types",
			names: []string{"otlp", "zipkin", "jaeger", "instana"},
			setup: func(t *testing.T) {
				t.Helper()
				t.Setenv("INSTANA_ENDPOINT_URL", "http://instana:1234")
				t.Setenv("INSTANA_AGENT_KEY", "foobar")
				t.Setenv(otelExporterOtlpTracesProtocolEnvKey, "grpc")
			},
			assert: func(t *testing.T, err error, expts []trace.SpanExporter) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, expts, 4)
				assert.IsType(t, &otlptrace.Exporter{}, expts[0])
				assert.IsType(t, &zipkin.Exporter{}, expts[1])
				assert.IsType(t, &jaeger.Exporter{}, expts[2])
				assert.IsType(t, &instana.Exporter{}, expts[3])
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			setup := x.IfThenElse(tc.setup == nil, func(t *testing.T) { t.Helper() }, tc.setup)
			setup(t)

			// WHEN
			expts, err := createSpanExporters(context.Background(), tc.names...)

			// THEN
			tc.assert(t, err, expts)
		})
	}
}
