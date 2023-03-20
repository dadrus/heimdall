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
	"sync"
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

	mu    sync.Mutex
	state map[string][]byte
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
		state:  make(map[string][]byte),
	}

	for idx, ep := range conf.Endpoints {
		if _, err := x.IfThenElseExec(conf.WatchInterval != nil && *conf.WatchInterval > 0,
			func() *gocron.Scheduler { return prov.s.Every(*conf.WatchInterval) },
			func() *gocron.Scheduler { return prov.s.Every(1 * time.Second).LimitRunsTo(1) },
		).Do(prov.watchChanges, ctx, ep); err != nil {
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

func (p *provider) watchChanges(ctx context.Context, rsf RuleSetFetcher) error {
	p.l.Debug().
		Str("_rule_provider_type", "http_endpoint").
		Str("_endpoint", rsf.ID()).
		Msg("Retrieving rule set")

	ruleSet, err := rsf.FetchRuleSet(ctx)
	if err != nil {
		p.l.Warn().
			Err(err).
			Str("_rule_provider_type", "http_endpoint").
			Str("_endpoint", rsf.ID()).
			Msg("Failed to fetch rule set")

		if errors.Is(err, heimdall.ErrInternal) || errors.Is(err, heimdall.ErrConfiguration) {
			return err
		}
	}

	changeType := x.IfThenElse(len(ruleSet.Rules) == 0, event.Remove, event.Create)

	stateUpdated, removeOld := p.checkAndUpdateState(changeType, rsf.ID(), ruleSet.Hash)
	if !stateUpdated {
		p.l.Debug().
			Str("_rule_provider_type", "http_endpoint").
			Str("_endpoint", rsf.ID()).
			Msg("No updates received")

		return nil
	}

	if removeOld {
		p.ruleSetChanged(event.RuleSetChangedEvent{
			Src:        "http_endpoint:" + rsf.ID(),
			ChangeType: event.Remove,
		})
	}

	p.ruleSetChanged(event.RuleSetChangedEvent{
		Src:        "http_endpoint:" + rsf.ID(),
		ChangeType: changeType,
		RuleSet:    ruleSet.Rules,
	})

	return nil
}

func (p *provider) checkAndUpdateState(changeType event.ChangeType, stateID string, newValue []byte) (bool, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	removeOld := false
	oldValue, known := p.state[stateID]

	switch changeType {
	case event.Remove:
		if !known {
			// nothing needs to be done, this rule set is not known
			return false, false
		}

		delete(p.state, stateID)
	case event.Create:
		if known && bytes.Equal(oldValue, newValue) {
			// nothing needs to be done, this rule set is already known
			return false, false
		} else if known {
			removeOld = true
		}

		p.state[stateID] = newValue
	}

	return true, removeOld
}

func (p *provider) ruleSetChanged(evt event.RuleSetChangedEvent) {
	p.l.Info().
		Str("_rule_provider_type", "http_endpoint").
		Str("_src", evt.Src).
		Str("_type", evt.ChangeType.String()).
		Msg("Rule set changed")
	p.q <- evt
}
