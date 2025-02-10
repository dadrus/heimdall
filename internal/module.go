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
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/app"
	cache "github.com/dadrus/heimdall/internal/cache/module"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/management"
	"github.com/dadrus/heimdall/internal/handler/metrics"
	"github.com/dadrus/heimdall/internal/handler/profiling"
	"github.com/dadrus/heimdall/internal/keyholder"
	"github.com/dadrus/heimdall/internal/otel"
	"github.com/dadrus/heimdall/internal/otel/metrics/certificate"
	"github.com/dadrus/heimdall/internal/rules"
	"github.com/dadrus/heimdall/internal/rules/mechanisms"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/watcher"
)

type appContext struct {
	w   watcher.Watcher
	khr keyholder.Registry
	co  certificate.Observer
	v   validation.Validator
	l   zerolog.Logger
	c   *config.Configuration
}

func (c *appContext) Watcher() watcher.Watcher                  { return c.w }
func (c *appContext) KeyHolderRegistry() keyholder.Registry     { return c.khr }
func (c *appContext) CertificateObserver() certificate.Observer { return c.co }
func (c *appContext) Validator() validation.Validator           { return c.v }
func (c *appContext) Logger() zerolog.Logger                    { return c.l }
func (c *appContext) Config() *config.Configuration             { return c.c }

var Module = fx.Options( //nolint:gochecknoglobals
	watcher.Module,
	keyholder.Module,
	fx.Provide(func(
		watcher watcher.Watcher,
		khr keyholder.Registry,
		observer certificate.Observer,
		validator validation.Validator,
		logger zerolog.Logger,
		conf *config.Configuration,
	) app.Context {
		return &appContext{
			w:   watcher,
			khr: khr,
			co:  observer,
			v:   validator,
			l:   logger,
			c:   conf,
		}
	}),
	otel.Module,
	cache.Module,
	mechanisms.Module,
	rules.Module,
	management.Module,
	metrics.Module,
	profiling.Module,
)
