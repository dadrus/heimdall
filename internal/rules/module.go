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

package rules

import (
	"context"

	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/rules/provider"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

const defaultQueueSize = 20

// Module is invoked on app bootstrapping.
// nolint: gochecknoglobals
var Module = fx.Options(
	fx.Provide(
		fx.Annotate(
			func(logger zerolog.Logger) event.RuleSetChangedEventQueue {
				logger.Debug().Msg("Creating rule set event queue.")

				return make(event.RuleSetChangedEventQueue, defaultQueueSize)
			},
			fx.OnStop(
				func(queue event.RuleSetChangedEventQueue, logger zerolog.Logger) {
					logger.Debug().Msg("Closing rule set event queue")

					close(queue)
				},
			),
		),
		NewRuleFactory,
		fx.Annotate(
			newRepository,
			fx.OnStart(func(ctx context.Context, o *repository) error { return o.Start(ctx) }),
			fx.OnStop(func(ctx context.Context, o *repository) error { return o.Stop(ctx) }),
		),
		func(r *repository) rule.Repository { return r },
		newRuleExecutor,
		NewRuleSetProcessor,
	),
	provider.Module,
)
