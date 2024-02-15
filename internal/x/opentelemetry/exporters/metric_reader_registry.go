// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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
	"os"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrUnsupportedMetricExporterType = errors.New("unsupported metric exporter type")
	ErrFailedCreatingMetricExporter  = errors.New("failed creating metric exporter")
)

var metricReaders = &registry[metric.Reader]{ //nolint:gochecknoglobals
	names: map[string]FactoryFunc[metric.Reader]{
		"otlp": func(ctx context.Context) (metric.Reader, error) {
			exp, err := createExporter(ctx)
			if err != nil {
				return nil, err
			}

			return metric.NewPeriodicReader(exp), nil
		},
		"prometheus": func(_ context.Context) (metric.Reader, error) {
			return prometheus.New()
		},
	},
}

func createExporter(ctx context.Context) (metric.Exporter, error) {
	val, ok := os.LookupEnv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL")
	if !ok {
		val = envOr("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
	}

	switch val {
	case "grpc":
		return otlpmetricgrpc.New(ctx)
	case "http/protobuf", "http/json":
		return otlpmetrichttp.New(ctx)
	default:
		return nil, errorchain.NewWithMessage(ErrUnsupportedOTLPProtocol, val)
	}
}

func createMetricsReaders(ctx context.Context, names ...string) ([]metric.Reader, error) {
	var exps []metric.Reader //nolint:prealloc

	for _, name := range names {
		if name == "none" {
			return []metric.Reader{metric.NewPeriodicReader(noopMetricExporter{})}, nil
		}

		create, ok := metricReaders.load(name)
		if !ok {
			return nil, errorchain.NewWithMessage(ErrUnsupportedMetricExporterType, name)
		}

		reader, err := create(ctx)
		if err != nil {
			return nil, errorchain.NewWithMessage(ErrFailedCreatingMetricExporter, name).CausedBy(err)
		}

		exps = append(exps, reader)
	}

	if len(exps) == 0 {
		create, _ := metricReaders.load("otlp")

		reader, err := create(ctx)
		if err != nil {
			return nil, errorchain.NewWithMessage(ErrFailedCreatingMetricExporter, "otlp").CausedBy(err)
		}

		return []metric.Reader{reader}, nil
	}

	return exps, nil
}
