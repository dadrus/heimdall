package httpendpoint

import (
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/event"
)

type httpEndpointProvider struct {
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

	logger.Info().Str("_rule_provider_type", "http_endpoint").Msg("Rule provider configured.")

	return nil
}
