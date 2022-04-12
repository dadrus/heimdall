package instana

import (
	"io"
	"io/ioutil"

	instana "github.com/instana/go-sensor"
	"github.com/opentracing/opentracing-go"
)

func New(serviceName string) (opentracing.Tracer, io.Closer, error) {
	opts := instana.DefaultOptions()

	if len(opts.Service) == 0 {
		opts.Service = serviceName
	}

	return instana.NewTracerWithOptions(opts), ioutil.NopCloser(nil), nil
}
