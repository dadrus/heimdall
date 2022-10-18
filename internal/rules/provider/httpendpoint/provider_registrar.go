package httpendpoint

import (
	"context"

	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/event"
)

type registrationArguments struct {
	fx.In

	Lifecycle fx.Lifecycle
	Config    config.Configuration
	Queue     event.RuleSetChangedEventQueue
	Cache     cache.Cache
}

func registerProvider(args registrationArguments, logger zerolog.Logger) error {
	if args.Config.Rules.Providers.HTTPEndpoint == nil {
		return nil
	}

	provider, err := newProvider(args.Config.Rules.Providers.HTTPEndpoint, args.Cache, args.Queue, logger)
	if err != nil {
		logger.Error().Err(err).
			Str("_rule_provider_type", "http_endpoint").
			Msg("Failed to create provider.")

		return err
	}

	logger.Info().
		Str("_rule_provider_type", "http_endpoint").
		Msg("Rule provider configured.")

	args.Lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error { return provider.Start(ctx) },
			OnStop:  func(ctx context.Context) error { return provider.Stop(ctx) },
		},
	)

	return nil
}
