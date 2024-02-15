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
	"os"

	instana "github.com/instana/go-otel-exporter"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/zipkin"
	"go.opentelemetry.io/otel/sdk/trace"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrFailedCreatingInstanaExporter = errors.New("failed creating instana exporter")
	ErrUnsupportedTracesExporterType = errors.New("unsupported traces exporter type")
	ErrUnsupportedOTLPProtocol       = errors.New("unsupported OTLP protocol")
	ErrFailedCreatingTracesExporter  = errors.New("failed creating traces exporter")
)

var spanExporters = &registry[trace.SpanExporter]{ //nolint:gochecknoglobals
	names: map[string]FactoryFunc[trace.SpanExporter]{
		"otlp": func(ctx context.Context) (trace.SpanExporter, error) {
			val, ok := os.LookupEnv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")
			if !ok {
				val = envOr("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
			}

			switch val {
			case "grpc":
				return otlptracegrpc.New(ctx)
			case "http/protobuf":
				return otlptracehttp.New(ctx)
			default:
				return nil, errorchain.NewWithMessage(ErrUnsupportedOTLPProtocol, val)
			}
		},
		"zipkin": func(_ context.Context) (trace.SpanExporter, error) {
			return zipkin.New("")
		},
		"instana": func(_ context.Context) (exp trace.SpanExporter, err error) { //nolint:nonamedreturns
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

func createSpanExporters(ctx context.Context, names ...string) ([]trace.SpanExporter, error) {
	var exps []trace.SpanExporter //nolint:prealloc

	for _, name := range names {
		if name == "none" {
			return []trace.SpanExporter{noopSpanExporter{}}, nil
		}

		createSpanExporter, ok := spanExporters.load(name)
		if !ok {
			return nil, errorchain.NewWithMessage(ErrUnsupportedTracesExporterType, name)
		}

		exporter, err := createSpanExporter(ctx)
		if err != nil {
			return nil, errorchain.NewWithMessage(ErrFailedCreatingTracesExporter, name).CausedBy(err)
		}

		exps = append(exps, exporter)
	}

	if len(exps) == 0 {
		create, _ := spanExporters.load("otlp")

		spanExp, err := create(ctx)
		if err != nil {
			return nil, errorchain.NewWithMessage(ErrFailedCreatingTracesExporter, "otlp").CausedBy(err)
		}

		return []trace.SpanExporter{spanExp}, nil
	}

	return exps, nil
}
