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
)

const defaultQueueSize = 20

// Module is invoked on app bootstrapping.
// nolint: gochecknoglobals
var Module = fx.Options(
	fx.Provide(func(logger zerolog.Logger) event.RuleSetChangedEventQueue {
		logger.Debug().Msg("Creating rule set event queue.")

		return make(event.RuleSetChangedEventQueue, defaultQueueSize)
	}),
	fx.Provide(
		func(queue event.RuleSetChangedEventQueue,
			ruleFactory RuleFactory,
			logger zerolog.Logger,
		) (Repository, RuleSetObserver) {
			repo := newRepository(queue, ruleFactory, logger)

			return repo, repo
		},
		NewRuleFactory,
	),
	fx.Invoke(
		registerRuleSetObserver,
		registerRuleSetChangedEventQueueCloser,
	),
	provider.Module,
)

func registerRuleSetChangedEventQueueCloser(
	lifecycle fx.Lifecycle,
	queue event.RuleSetChangedEventQueue,
	logger zerolog.Logger,
) {
	lifecycle.Append(fx.Hook{
		OnStop: func(ctx context.Context) error {
			logger.Debug().Msg("Closing rule set event queue")

			close(queue)

			return nil
		},
	})
}

func registerRuleSetObserver(lifecycle fx.Lifecycle, observer RuleSetObserver) {
	lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error { return observer.Start(ctx) },
			OnStop:  func(ctx context.Context) error { return observer.Stop(ctx) },
		},
	)
}
