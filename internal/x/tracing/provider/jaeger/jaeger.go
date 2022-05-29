package jaeger

import (
	"io"

	"github.com/opentracing/opentracing-go"
	"github.com/rs/zerolog"
	"github.com/uber/jaeger-client-go/config"
)

func New(serviceName string, log zerolog.Logger) (opentracing.Tracer, io.Closer, error) {
	cfg, err := config.FromEnv()
	if err != nil {
		return nil, nil, err
	}

	if len(cfg.ServiceName) == 0 {
		cfg.ServiceName = serviceName
	}

	return cfg.NewTracer(config.Logger(&logger{l: log}))
}
