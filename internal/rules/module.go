package rules

import (
	"context"

	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/rules/provider"
)

const defaultQueueSize = 20

// nolint
var Module = fx.Options(
	fx.Provide(func() provider.RuleSetChangedEventQueue {
		return make(provider.RuleSetChangedEventQueue, defaultQueueSize)
	}),
	fx.Provide(NewRepository),
	fx.Invoke(registerRuleDefinitionHandler),
	provider.Module,
)

func registerRuleDefinitionHandler(lifecycle fx.Lifecycle, logger zerolog.Logger, r Repository) {
	rdf, ok := r.(ruleSetDefinitionLoader)
	if !ok {
		logger.Error().Msg("No rule set definition loader available")

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
