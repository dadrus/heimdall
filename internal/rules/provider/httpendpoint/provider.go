package httpendpoint

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/endpoint"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type provider struct {
	e  endpoint.Endpoint
	wi time.Duration
	q  event.RuleSetChangedEventQueue
	l  zerolog.Logger
}

func newProvider(
	rawConf map[string]any,
	queue event.RuleSetChangedEventQueue,
	logger zerolog.Logger,
) (*provider, error) {
	type Config struct {
		Endpoint      endpoint.Endpoint `mapstructure:"endpoint"`
		WatchInterval *time.Duration    `mapstructure:"watch_interval"`
	}

	var conf Config
	if err := decodeConfig(rawConf, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to decode http_endpoint rule provider config").
			CausedBy(err)
	}

	if err := conf.Endpoint.Validate(); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration,
				"failed to validate http_endpoint rule provider endpoint configuration").
			CausedBy(err)
	}

	if len(conf.Endpoint.Method) != 0 {
		if conf.Endpoint.Method != http.MethodGet {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrConfiguration,
					"only GET is supported for the endpoint configuration of the http_endpoint provider")
		}
	} else {
		conf.Endpoint.Method = http.MethodGet
	}

	return &provider{
		e: conf.Endpoint,
		wi: x.IfThenElseExec(conf.WatchInterval != nil && *conf.WatchInterval > 0,
			func() time.Duration { return *conf.WatchInterval },
			func() time.Duration { return 0 * time.Second }),
		q: queue,
		l: logger,
	}, nil
}

func (p *provider) Start(ctx context.Context) error {
	p.l.Info().
		Str("_rule_provider_type", "http_endpoint").
		Msg("Starting rule definitions provider")

	if err := p.loadInitialRuleSet(ctx); err != nil {
		return err
	}

	return nil
}

func (p *provider) Stop(ctx context.Context) error {
	p.l.Info().
		Str("_rule_provider_type", "http_endpoint").
		Msg("Tearing down rule provider.")

	return nil
}

func (p *provider) loadInitialRuleSet(ctx context.Context) error {
	data, err := p.fetchRuleSet(ctx)
	if err != nil {
		return err
	}

	if len(data) == 0 {
		p.l.Warn().
			Str("_rule_provider_type", "http_endpoint").
			Str("_endpoint", p.e.URL).
			Msg("Ruleset is empty")

		return nil
	}

	p.ruleSetChanged(event.RuleSetChangedEvent{
		Src:        "http_endpoint:" + p.e.URL,
		Definition: data,
		ChangeType: event.Create,
	})

	return nil
}

func (p *provider) ruleSetChanged(evt event.RuleSetChangedEvent) {
	p.l.Info().
		Str("_rule_provider_type", "http_endpoint").
		Str("_src", evt.Src).
		Str("_type", evt.ChangeType.String()).
		Msg("Rule set changed")
	p.q <- evt
}

func (p *provider) fetchRuleSet(ctx context.Context) ([]byte, error) {
	p.l.Debug().Msg("Retrieving rule set from configured endpoint")

	req, err := p.e.CreateRequest(ctx, nil, nil)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed creating request").
			CausedBy(err)
	}

	client := p.e.CreateClient(req.URL.Hostname())

	resp, err := client.Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrCommunicationTimeout, "request to rule set endpoint timed out").
				CausedBy(err)
		}

		return nil, errorchain.
			NewWithMessage(heimdall.ErrCommunication, "request to rule set endpoint failed").
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
