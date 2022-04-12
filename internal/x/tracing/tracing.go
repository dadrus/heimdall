package tracing

import (
	"errors"
	"io"
	"os"

	"github.com/opentracing/opentracing-go"

	"github.com/dadrus/heimdall/internal/x/tracing/provider/instana"
	"github.com/dadrus/heimdall/internal/x/tracing/provider/jaeger"
)

var ErrOpentracingProvider = errors.New("no supported/configured opentracing provider")

func New(serviceName string) (opentracing.Tracer, io.Closer, error) {
	provider := os.Getenv("TRACING_PROVIDER")

	switch provider {
	case "jaeger":
		return jaeger.New(serviceName)
	case "instana":
		return instana.New(serviceName)
	default:
		return nil, nil, ErrOpentracingProvider
	}
}
