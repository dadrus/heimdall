package kubernetes

import (
	"context"

	"github.com/rs/zerolog"
	"go.uber.org/fx"
	"k8s.io/client-go/rest"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/event"
)

type ConfigFactory func() (*rest.Config, error)

type registrationArguments struct {
	fx.In

	Lifecycle fx.Lifecycle
	Config    config.Configuration
	K8sConfig ConfigFactory
	Queue     event.RuleSetChangedEventQueue
}

func registerProvider(args registrationArguments, logger zerolog.Logger) error {
	if args.Config.Rules.Providers.Kubernetes == nil {
		return nil
	}

	k8sConf, err := args.K8sConfig()
	if err != nil {
		logger.Error().Err(err).
			Str("_rule_provider_type", ProviderType).
			Msg("Failed to create provider.")

		return err
	}

	provider, err := newProvider(args.Config.Rules.Providers.Kubernetes, k8sConf, args.Queue, logger)
	if err != nil {
		logger.Error().Err(err).
			Str("_rule_provider_type", ProviderType).
			Msg("Failed to create provider.")

		return err
	}

	logger.Info().
		Str("_rule_provider_type", ProviderType).
		Msg("Rule provider configured.")

	args.Lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error { return provider.Start(ctx) },
			OnStop:  func(ctx context.Context) error { return provider.Stop(ctx) },
		},
	)

	return nil
}
