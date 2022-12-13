package tracing

import (
	"context"
	"fmt"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/opentelemetry/exporters"
)

type mockLifecycle struct{ mock.Mock }

func (m *mockLifecycle) Append(hook fx.Hook) { m.Called(hook) }

func TestInitializeOTEL(t *testing.T) {
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
			assert: func(t *testing.T, err error, _ propagation.TextMapPropagator, logged string) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, exporters.ErrFailedCreatingExporter)
			},
		},
		{
			uc:   "successful initialization",
			conf: config.TracingConfig{Enabled: true},
			setupMocks: func(t *testing.T, lcMock *mockLifecycle) {
				t.Helper()

				lcMock.On("Append",
					mock.MatchedBy(func(hook fx.Hook) bool {
						// should not fail and corresponding log statement shall be logged
						return hook.OnStop(context.Background()) == nil
					}),
				)
			},
			assert: func(t *testing.T, err error, propagator propagation.TextMapPropagator, logged string) {
				t.Helper()

				require.NoError(t, err)
				assert.Contains(t, logged, "tracing initialized")
				assert.Contains(t, logged, "Tearing down Opentelemetry provider")
				assert.Contains(t, logged, "OTEL Error")
				assert.Contains(t, logged, "test error")

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
			err := initializeOTEL(mock, &config.Configuration{Tracing: tc.conf}, logger)
			otel.Handle(fmt.Errorf("test error")) // nolint: goerr113
			propagator := otel.GetTextMapPropagator()

			// THEN
			tc.assert(t, err, propagator, tb.CollectedLog())
			mock.AssertExpectations(t)
		})
	}
}
