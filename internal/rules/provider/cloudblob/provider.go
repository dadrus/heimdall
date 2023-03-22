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

package cloudblob

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/go-co-op/gocron"
	"github.com/rs/zerolog"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/slicex"
)

type BucketState map[string][]byte

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
	processor rule.SetProcessor,
	logger zerolog.Logger,
) (*provider, error) {
	rawConf := conf.Rules.Providers.CloudBlob

	if rawConf == nil {
		return &provider{}, nil
	}

	type Config struct {
		Buckets       []*ruleSetEndpoint `mapstructure:"buckets"`
		WatchInterval *time.Duration     `mapstructure:"watch_interval"`
	}

	var providerConf Config
	if err := decodeConfig(rawConf, &providerConf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to decode cloud_blob rule provider config").
			CausedBy(err)
	}

	if len(providerConf.Buckets) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"no buckets configured for cloud_blob rule provider")
	}

	logger = logger.With().Str("_provider_type", "cloud_blob").Logger()

	ctx, cancel := context.WithCancel(context.Background())
	ctx = logger.With().Logger().WithContext(ctx)

	scheduler := gocron.NewScheduler(time.UTC)
	scheduler.SingletonModeAll()

	prov := &provider{
		p:          processor,
		l:          logger,
		s:          scheduler,
		cancel:     cancel,
		configured: true,
	}

	for idx, bucket := range providerConf.Buckets {
		if bucket.URL == nil {
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"missing url for #%d bucket in cloud_blob rule provider configuration", idx)
		}

		if _, err := x.IfThenElseExec(providerConf.WatchInterval != nil && *providerConf.WatchInterval > 0,
			func() *gocron.Scheduler { return prov.s.Every(*providerConf.WatchInterval) },
			func() *gocron.Scheduler { return prov.s.Every(1 * time.Second).LimitRunsTo(1) }).
			Do(prov.watchChanges, ctx, bucket); err != nil {
			return nil, errorchain.NewWithMessagef(heimdall.ErrInternal,
				"failed to create a rule provider worker to fetch rules sets from #%d cloud_blob", idx).
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

	p.l.Info().Msg("Tearing down rule provider.")

	p.s.Stop()
	p.cancel()

	return nil
}

func (p *provider) watchChanges(ctx context.Context, rsf RuleSetFetcher) error {
	p.l.Debug().Msg("Retrieving rule set")

	ruleSets, err := rsf.FetchRuleSets(ctx)
	if err != nil {
		p.l.Warn().
			Err(err).
			Str("_endpoint", rsf.ID()).
			Msg("Failed to fetch rule set")

		if errors.Is(err, heimdall.ErrInternal) || errors.Is(err, heimdall.ErrConfiguration) {
			return err
		}
	}

	state := p.getBucketState(rsf.ID())

	// if no rule sets are available and no rule sets were known from the past
	if len(ruleSets) == 0 && len(state) == 0 {
		p.l.Debug().Str("_endpoint", rsf.ID()).Msg("No updates received")

		return nil
	}

	p.ruleSetsUpdated(ruleSets, state, rsf.ID())

	return nil
}

func (p *provider) ruleSetsUpdated(ruleSets []*rule.SetConfiguration, state BucketState, buketID string) {
	// check which were present in the past and are not present now
	// and which are new
	currentIDs := toRuleSetIDs(ruleSets)
	oldIDs := maps.Keys(state)

	removedIDs := slicex.Subtract(oldIDs, currentIDs)
	newIDs := slicex.Subtract(currentIDs, oldIDs)

	for _, ID := range removedIDs {
		delete(state, ID)

		p.p.OnDeleted(&rule.SetConfiguration{SetMeta: rule.SetMeta{Source: ID}})
	}

	// check which rule sets are new and which are modified
	for _, ruleSet := range ruleSets {
		isNew := slices.Contains(newIDs, ruleSet.Source)
		hasChanged := !isNew && !bytes.Equal(state[ruleSet.Source], ruleSet.Hash)

		state[ruleSet.Source] = ruleSet.Hash

		if !isNew && !hasChanged {
			p.l.Debug().
				Str("_bucket", buketID).
				Str("_rule_set", ruleSet.Source).
				Msg("No updates received")

			continue
		}

		if isNew {
			p.p.OnCreated(ruleSet)
		} else if hasChanged {
			p.p.OnUpdated(ruleSet)
		}
	}
}

func (p *provider) getBucketState(key string) BucketState {
	value, _ := p.states.LoadOrStore(key, make(BucketState))

	return value.(BucketState) // nolint: forcetypeassert
}

func toRuleSetIDs(ruleSets []*rule.SetConfiguration) []string {
	currentIDs := make([]string, len(ruleSets))

	for idx, ruleSet := range ruleSets {
		currentIDs[idx] = ruleSet.Source
	}

	return currentIDs
}
