package httpendpoint

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/endpoint"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type provider struct {
	endpoint     endpoint.Endpoint
	watchChanges bool
	queue        event.RuleSetChangedEventQueue
	logger       zerolog.Logger
}

func newProvider(
	endpoint endpoint.Endpoint,
	watchChanges bool,
	queue event.RuleSetChangedEventQueue,
	logger zerolog.Logger,
) (*provider, error) {
	if err := endpoint.Validate(); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration,
				"failed to validate http_endpoint rule provider endpoint configuration").
			CausedBy(err)
	}

	return &provider{
		endpoint:     endpoint,
		watchChanges: watchChanges,
		queue:        queue,
		logger:       logger,
	}, nil
}

func (p *provider) Start() error {
	p.logger.Info().
		Str("_rule_provider_type", "http_endpoint").
		Msg("Rule provider configured.")

	return nil
}

func (p *provider) Stop() error {
	p.logger.Info().
		Str("_rule_provider_type", "http_endpoint").
		Msg("Tearing down rule provider.")

	return nil
}
