package jaeger

import (
	"io"

	"github.com/opentracing/opentracing-go"
	"github.com/uber/jaeger-client-go/config"
)

func New(serviceName string) (opentracing.Tracer, io.Closer, error) {
	cfg, err := config.FromEnv()
	if err != nil {
		return nil, nil, err
	}

	if len(cfg.ServiceName) == 0 {
		cfg.ServiceName = serviceName
	}

	return cfg.NewTracer(config.Logger(&stdLogger{}))
}
