package httpendpoint

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/endpoint"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type provider struct {
	e         endpoint.Endpoint
	c         cache.Cache
	wi        time.Duration
	q         event.RuleSetChangedEventQueue
	l         zerolog.Logger
	done      chan struct{} // Channel for sending a "quit message" to the watcher goroutine
	doneWatch chan struct{} // Channel to respond to the "quite message"
}

func newProvider(
	rawConf map[string]any,
	cch cache.Cache,
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
		c: cch,
		wi: x.IfThenElseExec(conf.WatchInterval != nil && *conf.WatchInterval > 0,
			func() time.Duration { return *conf.WatchInterval },
			func() time.Duration { return 0 * time.Second }),
		q:         queue,
		l:         logger,
		done:      make(chan struct{}),
		doneWatch: make(chan struct{}),
	}, nil
}

func (p *provider) Start(ctx context.Context) error {
	p.l.Info().
		Str("_rule_provider_type", "http_endpoint").
		Msg("Starting rule definitions provider")

	cchCtx := cache.WithContext(ctx, p.c)

	if err := p.loadRuleSet(cchCtx); err != nil {
		p.l.Error().Err(err).
			Str("_rule_provider_type", "http_endpoint").
			Msg("Failed loading initial rule sets")

		close(p.done)

		return err
	}

	go p.watchEndpoint(cchCtx)

	return nil
}

func (p *provider) Stop(ctx context.Context) error {
	p.l.Info().
		Str("_rule_provider_type", "http_endpoint").
		Msg("Tearing down rule provider.")

	select {
	case <-p.done:
		// already closed
		return nil
	default:
		// Send 'close' signal to goroutine.
		close(p.done)
	}

	// Wait for goroutine to close
	<-p.doneWatch

	return nil
}

func (p *provider) loadRuleSet(ctx context.Context) error {
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

func (p *provider) watchEndpoint(ctx context.Context) {
	defer func() {
		close(p.doneWatch)
	}()

	if p.wi <= 0 {
		p.l.Warn().
			Str("_rule_provider_type", "http_endpoint").
			Msg("Watcher for file_system provider is not configured. Updates to rules will have no effects.")

		return
	}

	ticker := time.NewTicker(p.wi)

	for {
		select {
		case <-ticker.C:
			if err := p.loadRuleSet(ctx); err != nil {
				p.l.Error().Err(err).
					Str("_rule_provider_type", "http_endpoint").
					Msg("Failed loading rule sets")
			}
		case <-p.done:
			p.l.Debug().
				Str("_rule_provider_type", "http_endpoint").
				Msg("Watcher events channel closed")

			return
		}
	}
}
