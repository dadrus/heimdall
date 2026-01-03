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

package otel

import (
	"context"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/x/opentelemetry/exporters"
)

func initMeterProvider(
	conf *config.Configuration,
	res *resource.Resource,
	logger zerolog.Logger,
	lifecycle fx.Lifecycle,
) error {
	if !conf.Metrics.Enabled {
		logger.Info().Msg("OpenTelemetry metrics disabled.")

		return nil
	}

	metricsReaders, err := exporters.NewMetricReaders(context.Background())
	if err != nil {
		return err
	}

	opts := make([]metric.Option, 0, len(metricsReaders)+2)
	opts = append(opts,
		metric.WithResource(res),
		metric.WithView(metric.NewView(
			metric.Instrument{
				Name: semconv.HTTPServerRequestDurationName,
				Kind: metric.InstrumentKindHistogram,
			},
			metric.Stream{
				Aggregation: metric.AggregationExplicitBucketHistogram{
					Boundaries: []float64{
						0.00001, 0.00005, // 10, 50µs
						0.0001, 0.00025, 0.0005, 0.00075, // 100, 250, 500, 750µs
						0.001, 0.0025, 0.005, 0.0075, // 1, 2.5, 5, 7.5ms
						0.01, 0.025, 0.05, 0.075, // 10, 25, 50, 75ms
						0.1, 0.25, 0.5, 0.75, // 100, 250, 500 750 ms
						1.0, 2.0, 5.0, // 1, 2, 5
					},
				},
			},
		)),
	)

	for _, reader := range metricsReaders {
		opts = append(opts, metric.WithReader(reader))
	}

	mp := metric.NewMeterProvider(opts...)
	otel.SetMeterProvider(mp)
	lifecycle.Append(fx.StopHook(mp.Shutdown))

	logger.Info().Msg("OpenTelemetry metrics initialized.")

	return nil
}
