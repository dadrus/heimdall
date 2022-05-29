package provider

import (
	"testing"

	instana "github.com/instana/go-sensor"
	"github.com/opentracing/opentracing-go"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uber/jaeger-client-go"
)

func TestNewProvider(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		provider string
		assert   func(t *testing.T, err error, tracer opentracing.Tracer)
	}{
		{
			uc:       "unsupported provider",
			provider: "foo",
			assert: func(t *testing.T, err error, tracer opentracing.Tracer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrUnsupportedProvider)
				assert.Contains(t, err.Error(), "foo")
			},
		},
		{
			uc:       "instana provider",
			provider: "instana",
			assert: func(t *testing.T, err error, tracer opentracing.Tracer) {
				t.Helper()

				require.NoError(t, err)
				_, ok := tracer.(instana.Tracer)
				assert.True(t, ok)
			},
		},
		{
			uc:       "jaeger provider",
			provider: "jaeger",
			assert: func(t *testing.T, err error, tracer opentracing.Tracer) {
				t.Helper()

				require.NoError(t, err)
				_, ok := tracer.(*jaeger.Tracer)
				assert.True(t, ok)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			tracer, closer, err := New(tc.provider, "foo", log.Logger)
			// THEN
			if err == nil {
				require.NoError(t, closer.Close())
			}

			tc.assert(t, err, tracer)
		})
	}
}
