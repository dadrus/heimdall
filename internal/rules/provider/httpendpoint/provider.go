// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package httpendpoint

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-co-op/gocron"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	config2 "github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type provider struct {
	p          rule.SetProcessor
	l          zerolog.Logger
	s          *gocron.Scheduler
	cancel     context.CancelFunc
	states     sync.Map
	configured bool
}

func newProvider(
	conf *config.Configuration,
	cch cache.Cache,
	processor rule.SetProcessor,
	logger zerolog.Logger,
) (*provider, error) {
	rawConf := conf.Rules.Providers.HTTPEndpoint

	if rawConf == nil {
		return &provider{}, nil
	}

	type Config struct {
		Endpoints     []*ruleSetEndpoint `mapstructure:"endpoints"`
		WatchInterval *time.Duration     `mapstructure:"watch_interval"`
	}

	var providerConf Config
	if err := decodeConfig(rawConf, &providerConf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to decode http_endpoint rule provider config").
			CausedBy(err)
	}

	if len(providerConf.Endpoints) == 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration,
				"no endpoints configured for http_endpoint rule provider")
	}

	for idx, ep := range providerConf.Endpoints {
		if err := ep.init(); err != nil {
			return nil, errorchain.
				NewWithMessagef(heimdall.ErrConfiguration,
					"failed to initialize #%d http_endpoint in the rule provider endpoint configuration", idx).
				CausedBy(err)
		}
	}

	logger = logger.With().Str("_provider_type", "http_endpoint").Logger()
	ctx, cancel := context.WithCancel(context.Background())
	ctx = logger.WithContext(cache.WithContext(ctx, cch))

	scheduler := gocron.NewScheduler(time.UTC)
	scheduler.SingletonModeAll()

	prov := &provider{
		p:          processor,
		l:          logger,
		s:          scheduler,
		cancel:     cancel,
		configured: true,
	}

	for idx, ep := range providerConf.Endpoints {
		if _, err := x.IfThenElseExec(providerConf.WatchInterval != nil && *providerConf.WatchInterval > 0,
			func() *gocron.Scheduler { return prov.s.Every(*providerConf.WatchInterval) },
			func() *gocron.Scheduler { return prov.s.Every(1 * time.Second).LimitRunsTo(1) },
		).Do(prov.watchChanges, ctx, ep); err != nil {
			return nil, errorchain.NewWithMessagef(heimdall.ErrInternal,
				"failed to create a rule provider worker to fetch rules sets from #%d http_endpoint", idx).
				CausedBy(err)
		}
	}

	logger.Info().Msg("Rule provider configured.")

	return prov, nil
}

func (p *provider) Start(_ context.Context) error {
	if !p.configured {
		return nil
	}

	p.l.Info().Msg("Starting rule definitions provider")

	p.s.StartAsync() //nolint:contextcheck

	return nil
}

func (p *provider) Stop(_ context.Context) error {
	if !p.configured {
		return nil
	}

	p.l.Info().Msg("Tearing down rule provider")

	p.s.Stop()
	p.cancel()

	return nil
}

func (p *provider) watchChanges(ctx context.Context, rsf RuleSetFetcher) error {
	p.l.Debug().
		Str("_endpoint", rsf.ID()).
		Msg("Retrieving rule set")

	ruleSet, err := rsf.FetchRuleSet(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			p.l.Debug().Msg("Watcher closed")

			return nil
		}

		p.l.Warn().Err(err).
			Str("_endpoint", rsf.ID()).
			Msg("Failed to fetch rule set")

		if !errors.Is(err, config2.ErrEmptyRuleSet) &&
			(errors.Is(err, heimdall.ErrInternal) || errors.Is(err, heimdall.ErrConfiguration)) {
			return err
		}

		ruleSet = &config2.RuleSet{
			MetaData: config2.MetaData{
				Source:  fmt.Sprintf("http_endpoint:%s", rsf.ID()),
				ModTime: time.Now(),
			},
		}
	}

	if err = p.ruleSetsUpdated(ruleSet, rsf.ID()); err != nil {
		p.l.Warn().Err(err).
			Str("_src", rsf.ID()).
			Msg("Failed to apply rule set changes")
	}

	return nil
}

func (p *provider) ruleSetsUpdated(ruleSet *config2.RuleSet, stateID string) error {
	var hash []byte

	if value, ok := p.states.Load(stateID); ok { //nolint:nestif
		hash = value.([]byte) // nolint: forcetypeassert

		// rule set was known
		if len(ruleSet.Rules) == 0 {
			// rule set removed
			if err := p.p.OnDeleted(ruleSet); err != nil {
				return err
			}

			p.states.Delete(stateID)

			return nil
		} else if !bytes.Equal(hash, ruleSet.Hash) {
			// rule set updated
			if err := p.p.OnUpdated(ruleSet); err != nil {
				return err
			}

			p.states.Store(stateID, ruleSet.Hash)

			return nil
		}
	} else if len(ruleSet.Rules) != 0 {
		// previously unknown rule set
		if err := p.p.OnCreated(ruleSet); err != nil {
			return err
		}

		p.states.Store(stateID, ruleSet.Hash)

		return nil
	}

	p.l.Debug().
		Str("_endpoint", stateID).
		Msg("No updates received")

	return nil
}
