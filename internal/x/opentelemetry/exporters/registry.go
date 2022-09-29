package exporters

import (
	"context"
	"errors"
	"fmt"
	"sync"

	instana "github.com/instana/go-otel-exporter"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/zipkin"
	"go.opentelemetry.io/otel/sdk/trace"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrFailedCreatingInstanaExporter = errors.New("failed creating instana exporter")
	ErrUnsupportedExporterType       = errors.New("unsupported exporter type")
	ErrUnsupportedOTLPProtocol       = errors.New("unsupported OTLP protocol")
	ErrDuplicateRegistration         = errors.New("duplicate registration")
	ErrFailedCreatingExporter        = errors.New("failed creating exporter")
)

const otelExporterOtlpTracesProtocolEnvKey = "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"

type SpanExporterFactory func(ctx context.Context) (trace.SpanExporter, error)

var exporters = &registry{ //nolint:gochecknoglobals
	names: map[string]SpanExporterFactory{
		"otlp": func(ctx context.Context) (trace.SpanExporter, error) {
			switch envOr(otelExporterOtlpTracesProtocolEnvKey, "http/protobuf") {
			case "grpc":
				return otlptracegrpc.New(ctx)
			case "http/protobuf":
				return otlptracehttp.New(ctx)
			default:
				return nil, ErrUnsupportedOTLPProtocol
			}
		},
		"zipkin": func(ctx context.Context) (trace.SpanExporter, error) {
			return zipkin.New("")
		},
		"jaeger": func(ctx context.Context) (trace.SpanExporter, error) {
			return jaeger.New(jaeger.WithAgentEndpoint())
		},
		"instana": func(ctx context.Context) (trace.SpanExporter, error) {
			var (
				err error
				ok  bool
			)

			defer func() {
				if r := recover(); r != nil {
					if err, ok = r.(error); !ok {
						err = errorchain.NewWithMessage(ErrFailedCreatingInstanaExporter, fmt.Sprintf("%v", r))
					}
				}
			}()

			return instana.New(), err
		},
	},
}

type registry struct {
	mu    sync.Mutex
	names map[string]SpanExporterFactory
}

func (r *registry) load(key string) (SpanExporterFactory, bool) {
	r.mu.Lock()
	f, ok := r.names[key]
	r.mu.Unlock()

	return f, ok
}

func (r *registry) store(key string, value SpanExporterFactory) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.names[key]; ok {
		return errorchain.NewWithMessage(ErrDuplicateRegistration, key)
	}

	r.names[key] = value

	return nil
}

func RegisterSpanExporterFactory(name string, factory SpanExporterFactory) {
	if err := exporters.store(name, factory); err != nil {
		panic(err)
	}
}

func spanExporters(ctx context.Context, names ...string) ([]trace.SpanExporter, error) {
	var exps []trace.SpanExporter //nolint:prealloc

	for _, name := range names {
		if name == "none" {
			return []trace.SpanExporter{noopExporter{}}, nil
		}

		createSpanExporter, ok := exporters.load(name)
		if !ok {
			return nil, errorchain.NewWithMessage(ErrUnsupportedExporterType, name)
		}

		exporter, err := createSpanExporter(ctx)
		if err != nil {
			return nil, errorchain.NewWithMessage(ErrFailedCreatingExporter, name).CausedBy(err)
		}

		exps = append(exps, exporter)
	}

	if len(exps) == 0 {
		create, _ := exporters.load("otlp")

		spanExp, err := create(ctx)
		if err != nil {
			return nil, errorchain.NewWithMessage(ErrFailedCreatingExporter, "otlp").CausedBy(err)
		}

		return []trace.SpanExporter{spanExp}, nil
	}

	return exps, nil
}
