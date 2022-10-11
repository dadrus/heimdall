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

type httpEndpointProvider struct {
	endpoint     endpoint.Endpoint
	watchChanges bool
	queue        event.RuleSetChangedEventQueue
	logger       zerolog.Logger
}

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

	args.Lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				return provider.Start()
			},
			OnStop: func(ctx context.Context) error {
				return provider.Stop()
			},
		},
	)

	logger.Info().Str("_rule_provider_type", "http_endpoint").Msg("Rule provider configured.")

	return nil
}

func newProvider(
	endpoint endpoint.Endpoint,
	watchChanges bool,
	queue event.RuleSetChangedEventQueue,
	logger zerolog.Logger,
) (*httpEndpointProvider, error) {
	if err := endpoint.Validate(); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration,
				"failed to validate http_endpoint rule provider endpoint configuration").
			CausedBy(err)
	}

	return &httpEndpointProvider{
		endpoint:     endpoint,
		watchChanges: watchChanges,
		queue:        queue,
		logger:       logger,
	}, nil
}

func (p *httpEndpointProvider) Start() error {
	return nil
}

func (p *httpEndpointProvider) Stop() error {
	return nil
}
