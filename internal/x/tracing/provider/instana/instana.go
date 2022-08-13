package instana

import (
	"io"

	instana "github.com/instana/go-sensor"
	"github.com/opentracing/opentracing-go"
	"github.com/rs/zerolog"
)

func New(serviceName string, log zerolog.Logger) (opentracing.Tracer, io.Closer, error) {
	instana.SetLogger(&logger{l: log})

	opts := instana.DefaultOptions()
	if len(opts.Service) == 0 {
		opts.Service = serviceName
	}

	return instana.NewTracerWithOptions(opts), io.NopCloser(nil), nil
}
