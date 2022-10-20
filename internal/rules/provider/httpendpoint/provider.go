package httpendpoint

import (
	"context"
	"errors"
	"time"

	"github.com/go-co-op/gocron"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ruleSetFetcher interface {
	fetchRuleSet(ctx context.Context) ([]config.RuleConfig, error)
	url() string
}

type provider struct {
	q      event.RuleSetChangedEventQueue
	l      zerolog.Logger
	s      *gocron.Scheduler
	cancel context.CancelFunc
}

func newProvider(
	rawConf map[string]any,
	cch cache.Cache,
	queue event.RuleSetChangedEventQueue,
	logger zerolog.Logger,
) (*provider, error) {
	type Config struct {
		Endpoints     []*ruleSetEndpoint `mapstructure:"endpoints"`
		WatchInterval *time.Duration     `mapstructure:"watch_interval"`
	}

	var conf Config
	if err := decodeConfig(rawConf, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to decode http_endpoint rule provider config").
			CausedBy(err)
	}

	if len(conf.Endpoints) == 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration,
				"no endpoints configured for http_endpoint rule provider")
	}

	for idx, ep := range conf.Endpoints {
		if err := ep.init(); err != nil {
			return nil, errorchain.
				NewWithMessagef(heimdall.ErrConfiguration,
					"failed to initialize #%d http_endpoint in the rule provider endpoint configuration", idx).
				CausedBy(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	ctx = logger.With().
		Str("_rule_provider_type", "http_endpoint").
		Logger().
		WithContext(cache.WithContext(ctx, cch))

	scheduler := gocron.NewScheduler(time.UTC)
	scheduler.SingletonModeAll()

	prov := &provider{
		q:      queue,
		l:      logger,
		s:      scheduler,
		cancel: cancel,
	}

	for idx, ep := range conf.Endpoints {
		var err error

		if conf.WatchInterval != nil && *conf.WatchInterval > 0 {
			_, err = scheduler.Every(*conf.WatchInterval).Do(prov.watchChanges, ctx, ep)
		} else {
			_, err = scheduler.Every(1*time.Second).LimitRunsTo(1).Do(prov.watchChanges, ctx, ep)
		}

		if err != nil {
			return nil, errorchain.NewWithMessagef(heimdall.ErrInternal,
				"failed to create a rule provider worker to fetch rules sets from #%d http_endpoint", idx).
				CausedBy(err)
		}
	}

	return prov, nil
}

func (p *provider) Start(_ context.Context) error {
	p.l.Info().
		Str("_rule_provider_type", "http_endpoint").
		Msg("Starting rule definitions provider")

	p.s.StartAsync() //nolint:contextcheck

	return nil
}

func (p *provider) Stop(_ context.Context) error {
	p.l.Info().
		Str("_rule_provider_type", "http_endpoint").
		Msg("Tearing down rule provider.")

	p.cancel()
	p.s.Stop()

	return nil
}

func (p *provider) watchChanges(ctx context.Context, rsf ruleSetFetcher) error {
	p.l.Debug().
		Str("_rule_provider_type", "http_endpoint").
		Str("_endpoint", rsf.url()).
		Msg("Retrieving rule set")

	ruleSet, err := rsf.fetchRuleSet(ctx)
	if err != nil {
		p.l.Warn().
			Err(err).
			Str("_rule_provider_type", "http_endpoint").
			Msg("Failed to fetch rule set")

		if !errors.Is(err, heimdall.ErrCommunication) {
			return err
		}
	}

	evt := event.RuleSetChangedEvent{
		Src:        "http_endpoint:" + rsf.url(),
		ChangeType: x.IfThenElse(len(ruleSet) == 0, event.Remove, event.Create),
		RuleSet:    ruleSet,
	}

	p.l.Info().
		Str("_rule_provider_type", "http_endpoint").
		Str("_src", evt.Src).
		Str("_type", evt.ChangeType.String()).
		Msg("Rule set changed")

	p.q <- evt

	return nil
}
