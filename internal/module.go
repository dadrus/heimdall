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
	"github.com/dadrus/heimdall/internal/keyregistry/v2"
	"github.com/dadrus/heimdall/internal/otel"
	"github.com/dadrus/heimdall/internal/rules"
	"github.com/dadrus/heimdall/internal/rules/mechanisms"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/watcher"
)

type appContext struct {
	w  watcher.Watcher
	kr keyregistry.Registry
	sm secrets.Manager
	d  encoding.DecoderFactory
	v  validation.Validator
	l  zerolog.Logger
	m  metric.Meter
	c  *config.Configuration
}

func (c *appContext) Watcher() watcher.Watcher                { return c.w }
func (c *appContext) KeyRegistry() keyregistry.Registry       { return c.kr }
func (c *appContext) SecretsManager() secrets.Manager         { return c.sm }
func (c *appContext) DecoderFactory() encoding.DecoderFactory { return c.d }
func (c *appContext) Validator() validation.Validator         { return c.v }
func (c *appContext) Logger() zerolog.Logger                  { return c.l }
func (c *appContext) Meter() metric.Meter                     { return c.m }
func (c *appContext) Config() *config.Configuration           { return c.c }

var Module = fx.Options( //nolint:gochecknoglobals
	otel.Module,
	watcher.Module,
	keyregistry.Module,
	secrets.Module,
	fx.Provide(func(validator validation.Validator) encoding.DecoderFactory {
		return encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct))
	}),
	fx.Provide(func(
		watcher watcher.Watcher,
		kr keyregistry.Registry,
		sm secrets.Manager,
		decoderFactory encoding.DecoderFactory,
		validator validation.Validator,
		logger zerolog.Logger,
		meter metric.Meter,
		conf *config.Configuration,
	) app.Context {
		return &appContext{
			w:  watcher,
			kr: kr,
			sm: sm,
			d:  decoderFactory,
			v:  validator,
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
