package cloudblob

import (
	"context"
	"time"

	"github.com/go-co-op/gocron"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type provider struct {
	q      event.RuleSetChangedEventQueue
	l      zerolog.Logger
	s      *gocron.Scheduler
	cancel context.CancelFunc

	state map[string][]byte
}

func newProvider(
	rawConf map[string]any,
	cch cache.Cache,
	queue event.RuleSetChangedEventQueue,
	logger zerolog.Logger,
) (*provider, error) {
	type Config struct {
		Buckets       []*ruleSetEndpoint `mapstructure:"buckets"`
		WatchInterval *time.Duration     `mapstructure:"watch_interval"`
	}

	var conf Config
	if err := decodeConfig(rawConf, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to decode cloud_blob rule provider config").
			CausedBy(err)
	}

	if len(conf.Buckets) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"no endpoints configured for cloud_blob rule provider")
	}

	ctx, cancel := context.WithCancel(context.Background())
	ctx = logger.With().
		Str("_rule_provider_type", "cloud_blob").
		Logger().
		WithContext(cache.WithContext(ctx, cch))

	scheduler := gocron.NewScheduler(time.UTC)
	scheduler.SingletonModeAll()

	prov := &provider{
		q:      queue,
		l:      logger,
		s:      scheduler,
		cancel: cancel,
		state:  make(map[string][]byte),
	}

	for idx, bucket := range conf.Buckets {
		if _, err := x.IfThenElseExec(conf.WatchInterval != nil && *conf.WatchInterval > 0,
			func() *gocron.Scheduler { return prov.s.Every(*conf.WatchInterval) },
			func() *gocron.Scheduler { return prov.s.Every(1 * time.Second).LimitRunsTo(1) }).
			Do(prov.watchChanges, ctx, bucket); err != nil {
			return nil, errorchain.NewWithMessagef(heimdall.ErrInternal,
				"failed to create a rule provider worker to fetch rules sets from #%d cloud_blob", idx).
				CausedBy(err)
		}
	}

	return prov, nil
}

func (p *provider) Start(_ context.Context) error {
	p.l.Info().
		Str("_rule_provider_type", "cloud_blob").
		Msg("Starting rule definitions provider")

	p.s.StartAsync() //nolint:contextcheck

	return nil
}

func (p *provider) Stop(_ context.Context) error {
	p.l.Info().
		Str("_rule_provider_type", "cloud_blob").
		Msg("Tearing down rule provider.")

	p.cancel()
	p.s.Stop()

	return nil
}

func (p *provider) watchChanges(ctx context.Context, fetcher RuleSetFetcher) error {
	p.l.Debug().
		Str("_rule_provider_type", "cloud_blob").
		Msg("Retrieving rule set")

	return nil
}
