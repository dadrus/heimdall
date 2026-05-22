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

package internal

import (
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/handler/management"
	"github.com/dadrus/heimdall/internal/handler/metrics"
	"github.com/dadrus/heimdall/internal/handler/profiling"
	"github.com/dadrus/heimdall/internal/keyregistry"
	"github.com/dadrus/heimdall/internal/otel"
	"github.com/dadrus/heimdall/internal/rules"
	"github.com/dadrus/heimdall/internal/rules/mechanisms"
	"github.com/dadrus/heimdall/internal/secrets"
)

type appContext struct {
	kr keyregistry.Registry
	sr secrets.Resolver
	d  encoding.DecoderFactory
	l  zerolog.Logger
	m  metric.Meter
	c  *config.Configuration
}

func (c *appContext) KeyRegistry() keyregistry.Registry       { return c.kr }
func (c *appContext) SecretResolver() secrets.Resolver        { return c.sr }
func (c *appContext) DecoderFactory() encoding.DecoderFactory { return c.d }
func (c *appContext) Logger() zerolog.Logger                  { return c.l }
func (c *appContext) Meter() metric.Meter                     { return c.m }
func (c *appContext) Config() *config.Configuration           { return c.c }

var Module = fx.Options( //nolint:gochecknoglobals
	otel.Module,
	keyregistry.Module,
	secrets.Module,
	fx.Provide(func(
		kr keyregistry.Registry,
		sr secrets.Resolver,
		decoderFactory encoding.DecoderFactory,
		logger zerolog.Logger,
		meter metric.Meter,
		conf *config.Configuration,
	) app.Context {
		return &appContext{
			kr: kr,
			sr: sr,
			d:  decoderFactory,
			l:  logger,
			m:  meter,
			c:  conf,
		}
	}),
	cache.Module,
	mechanisms.Module,
	rules.Module,
	management.Module,
	metrics.Module,
	profiling.Module,
)
