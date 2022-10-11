package httpendpoint

import (
	"context"

	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/endpoint"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type registrationArguments struct {
	fx.In

	Lifecycle fx.Lifecycle
	Config    config.Configuration
	Queue     event.RuleSetChangedEventQueue
}

func registerProvider(args registrationArguments, logger zerolog.Logger) error {
	if args.Config.Rules.Providers.HTTPEndpoint == nil {
		return nil
	}

	type Config struct {
		Endpoint endpoint.Endpoint `mapstructure:"endpoint"`
		Watch    bool              `mapstructure:"watch"`
	}

	var conf Config

	if err := decodeConfig(args.Config.Rules.Providers.HTTPEndpoint, &conf); err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to decode http_endpoint rule provider config").
			CausedBy(err)
	}

	provider, err := newProvider(conf.Endpoint, conf.Watch, args.Queue, logger)
	if err != nil {
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
