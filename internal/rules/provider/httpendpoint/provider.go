package httpendpoint

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/dadrus/heimdall/internal/endpoint"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/rs/zerolog"
)

type provider struct {
	e endpoint.Endpoint
	w bool
	q event.RuleSetChangedEventQueue
	l zerolog.Logger
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
		e: endpoint,
		w: watchChanges,
		q: queue,
		l: logger,
	}, nil
}

func (p *provider) Start(ctx context.Context) error {
	p.l.Info().
		Str("_rule_provider_type", "http_endpoint").
		Msg("Rule provider configured.")

	return nil
}

func (p *provider) Stop(ctx context.Context) error {
	p.l.Info().
		Str("_rule_provider_type", "http_endpoint").
		Msg("Tearing down rule provider.")

	return nil
}

func (p *provider) fetchRuleSet(ctx context.Context) ([]byte, error) {
	logger := zerolog.Ctx(ctx)

	logger.Debug().Msg("Retrieving JWKS from configured endpoint")

	req, err := p.e.CreateRequest(ctx, nil, nil)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed creating request").
			CausedBy(err)
	}

	resp, err := p.e.CreateClient(req.URL.Hostname()).Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrCommunicationTimeout, "request to JWKS endpoint timed out").
				CausedBy(err)
		}

		return nil, errorchain.
			NewWithMessage(heimdall.ErrCommunication, "request to JWKS endpoint failed").
			CausedBy(err)
	}

	defer resp.Body.Close()

	return p.readRuleSet(resp)
}

func (p *provider) readRuleSet(resp *http.Response) ([]byte, error) {
	if !(resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices) {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrCommunication, "unexpected response. code: %v", resp.StatusCode)
	}

	rawData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to read response").
			CausedBy(err)
	}

	return rawData, nil
}
