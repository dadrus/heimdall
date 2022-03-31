package rules

import (
	"context"

	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/rules/provider"
)

const defaultQueueSize = 20

var Module = fx.Options(
	fx.Provide(func() provider.RuleSetChangedEventQueue {
		return make(provider.RuleSetChangedEventQueue, defaultQueueSize)
	}),
	fx.Provide(NewRepository),
	fx.Invoke(registerRuleDefinitionHandler),
	provider.Module,
)

func registerRuleDefinitionHandler(lifecycle fx.Lifecycle, logger zerolog.Logger, r Repository) {
	rdf, ok := r.(ruleDefinitionHandler)
	if !ok {
		logger.Error().Msg("No rule definition handler available")

		return
	}

	lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				logger.Info().Msg("Starting rule definition handler")
				rdf.Start()

				return nil
			},
			OnStop: func(ctx context.Context) error {
				logger.Info().Msg("Tearing down rule definition handler")
				rdf.Stop()

				return nil
			},
		},
	)
}
