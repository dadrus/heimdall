package httpendpoint

import (
	"github.com/rs/zerolog"

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
