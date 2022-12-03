package httpendpoint

import (
	"context"

	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/x/errorchain"
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
		return errorchain.NewWithMessage(heimdall.ErrInternal, "failed to create http_endpoint provider").
			CausedBy(err)
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
