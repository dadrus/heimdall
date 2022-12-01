package cloudblob

import (
	"context"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"

	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/event"
)

type registrationArguments struct {
	fx.In

	Lifecycle fx.Lifecycle
	Config    config.Configuration
	Queue     event.RuleSetChangedEventQueue
}

func registerProvider(args registrationArguments, logger zerolog.Logger) error {
	if args.Config.Rules.Providers.CloudBlob == nil {
		return nil
	}

	provider, err := newProvider(args.Config.Rules.Providers.CloudBlob, args.Queue, logger)
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal, "failed to create cloud_blob provider").
			CausedBy(err)
	}

	logger.Info().
		Str("_rule_provider_type", "cloud_blob").
		Msg("Rule provider configured.")

	args.Lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error { return provider.Start(ctx) },
			OnStop:  func(ctx context.Context) error { return provider.Stop(ctx) },
		},
	)

	return nil
}
