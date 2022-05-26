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
	fx.Provide(NewRepository, NewRuleFactory),
	fx.Invoke(registerRuleDefinitionHandler, registerRuleSetChangedEventQueueCloser),
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

func registerRuleDefinitionHandler(lifecycle fx.Lifecycle, logger zerolog.Logger, r Repository) {
	rdf, ok := r.(ruleSetDefinitionLoader)
	if !ok {
		logger.Fatal().Msg("No rule set definition loader available")

		return
	}

	lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				return rdf.Start()
			},
			OnStop: func(ctx context.Context) error {
				return rdf.Stop()
			},
		},
	)
}
