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

	opts := make([]metric.Option, len(metricsReaders)+1)
	opts[0] = metric.WithResource(res)

	for i, reader := range metricsReaders {
		opts[i+1] = metric.WithReader(reader)
	}

	mp := metric.NewMeterProvider(opts...)
	otel.SetMeterProvider(mp)
	lifecycle.Append(fx.StopHook(mp.Shutdown))

	logger.Info().Msg("OpenTelemetry metrics initialized.")

	return nil
}
