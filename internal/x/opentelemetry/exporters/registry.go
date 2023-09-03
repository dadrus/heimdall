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
	"sync"

	instana "github.com/instana/go-otel-exporter"
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
	ErrDuplicateRegistration         = errors.New("duplicate exporter registration")
	ErrFailedCreatingExporter        = errors.New("failed creating exporter")
)

const otelExporterOtlpTracesProtocolEnvKey = "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"

type SpanExporterFactory func(ctx context.Context) (trace.SpanExporter, error)

var exporters = &registry{ //nolint:gochecknoglobals
	names: map[string]SpanExporterFactory{
		"otlp": func(ctx context.Context) (trace.SpanExporter, error) {
			val := envOr(otelExporterOtlpTracesProtocolEnvKey, "http/protobuf")

			switch val {
			case "grpc":
				return otlptracegrpc.New(ctx)
			case "http/protobuf":
				return otlptracehttp.New(ctx)
			default:
				return nil, errorchain.NewWithMessage(ErrUnsupportedOTLPProtocol, val)
			}
		},
		"zipkin": func(ctx context.Context) (trace.SpanExporter, error) {
			return zipkin.New("")
		},
		"instana": func(ctx context.Context) (exp trace.SpanExporter, err error) { //nolint:nonamedreturns
			defer func() {
				if r := recover(); r != nil {
					err = errorchain.NewWithMessage(ErrFailedCreatingInstanaExporter, fmt.Sprintf("%s", r))
				}
			}()

			exp = instana.New()

			return exp, err
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

	if r.names == nil {
		r.names = map[string]SpanExporterFactory{key: value}

		return nil
	}

	if _, ok := r.names[key]; ok {
		return errorchain.NewWithMessage(ErrDuplicateRegistration, key)
	}

	r.names[key] = value

	return nil
}

func (r *registry) remove(key string) {
	r.mu.Lock()
	delete(r.names, key)
	r.mu.Unlock()
}

func RegisterSpanExporterFactory(name string, factory SpanExporterFactory) {
	if err := exporters.store(name, factory); err != nil {
		panic(err)
	}
}

func createSpanExporters(ctx context.Context, names ...string) ([]trace.SpanExporter, error) {
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
