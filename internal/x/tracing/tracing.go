package tracing

import (
	"errors"
	"io"

	"github.com/opentracing/opentracing-go"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/x/tracing/provider/instana"
	"github.com/dadrus/heimdall/internal/x/tracing/provider/jaeger"
)

var ErrOpentracingProvider = errors.New("no supported/configured opentracing provider")

func New(provider, serviceName string, log zerolog.Logger) (opentracing.Tracer, io.Closer, error) {
	switch provider {
	case "jaeger":
		return jaeger.New(serviceName, log)
	case "instana":
		return instana.New(serviceName, log)
	default:
		return nil, nil, ErrOpentracingProvider
	}
}
