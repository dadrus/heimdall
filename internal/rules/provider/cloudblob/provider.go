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
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	rule_config "github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/slicex"
)

type BucketState map[string][]byte

type Provider struct {
	p          rule.SetProcessor
	l          zerolog.Logger
	s          gocron.Scheduler
	app        app.Context
	cancel     context.CancelFunc
	states     sync.Map
	configured bool
}

func NewProvider(app app.Context, rsp rule.SetProcessor) (*Provider, error) {
	conf := app.Config()
	logger := app.Logger()
	rawConf := conf.Providers.CloudBlob

	if rawConf == nil {
		return &Provider{}, nil
	}

	type Config struct {
		Buckets       []*ruleSetEndpoint `mapstructure:"buckets"`
		WatchInterval *time.Duration     `mapstructure:"watch_interval"`
	}

	var providerConf Config
	if err := decodeConfig(rawConf, &providerConf); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed to decode cloud_blob rule provider config").CausedBy(err)
	}

	if len(providerConf.Buckets) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"no buckets configured for cloud_blob rule provider")
	}

	logger = logger.With().Str("_provider_type", "cloud_blob").Logger()

	ctx, cancel := context.WithCancel(context.Background())
	ctx = logger.With().Logger().WithContext(ctx)

	scheduler, err := gocron.NewScheduler(
		gocron.WithLocation(time.UTC),
		gocron.WithGlobalJobOptions(
			gocron.WithSingletonMode(gocron.LimitModeReschedule),
			gocron.WithStartAt(gocron.WithStartImmediately()),
		),
	)
	if err != nil {
		cancel()

		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed creating scheduler for cloud_blob rule provider").CausedBy(err)
	}

	prov := &Provider{
		p:          rsp,
		l:          logger,
		s:          scheduler,
		app:        app,
		cancel:     cancel,
		configured: true,
	}

	for idx, bucket := range providerConf.Buckets {
		if bucket.URL == nil {
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"missing url for #%d bucket in cloud_blob rule provider configuration", idx)
		}

		var definition gocron.JobDefinition

		if providerConf.WatchInterval != nil && *providerConf.WatchInterval > 0 {
			definition = gocron.DurationJob(*providerConf.WatchInterval)
		} else {
			logger.Info().Msg("Watching of rules is not configured. Updates to rules will have no effect.")

			definition = gocron.OneTimeJob(gocron.OneTimeJobStartImmediately())
		}

		if _, err = prov.s.NewJob(definition, gocron.NewTask(prov.watchChanges, ctx, bucket)); err != nil {
			return nil, errorchain.NewWithMessagef(heimdall.ErrInternal,
				"failed to create a rule provider worker to fetch rules sets from #%d cloud_blob", idx).
				CausedBy(err)
		}
	}

	logger.Info().Msg("Rule provider configured.")

	return prov, nil
}

func (p *Provider) Start(_ context.Context) error {
	if !p.configured {
		return nil
	}

	p.l.Info().Msg("Starting rule definitions provider")

	go p.s.Start()

	return nil
}

func (p *Provider) Stop(_ context.Context) error {
	if !p.configured {
		return nil
	}

	p.l.Info().Msg("Tearing down rule provider")

	p.cancel()

	return p.s.Shutdown()
}

func (p *Provider) watchChanges(ctx context.Context, rsf RuleSetFetcher) error {
	p.l.Debug().Msg("Retrieving rule set")

	ruleSets, err := rsf.FetchRuleSets(ctx, p.app)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			p.l.Debug().Msg("Watcher closed")

			return nil
		}

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

	if err = p.ruleSetsUpdated(ruleSets, state, rsf.ID()); err != nil {
		p.l.Warn().Err(err).Str("_endpoint", rsf.ID()).Msg("Failed to apply rule set changes")
	}

	return nil
}

func (p *Provider) ruleSetsUpdated(ruleSets []*rule_config.RuleSet, state BucketState, buketID string) error {
	// check which were present in the past and are not present now
	// and which are new
	currentIDs := toRuleSetIDs(ruleSets)
	oldIDs := slices.Collect(maps.Keys(state))

	removedIDs := slicex.Subtract(oldIDs, currentIDs)
	newIDs := slicex.Subtract(currentIDs, oldIDs)

	for _, ID := range removedIDs {
		conf := &rule_config.RuleSet{
			MetaData: rule_config.MetaData{
				Source:  "blob:" + ID,
				ModTime: time.Now(),
			},
		}

		if err := p.p.OnDeleted(conf); err != nil {
			return err
		}

		delete(state, ID)
	}

	// check which rule sets are new and which are modified
	for _, ruleSet := range ruleSets {
		isNew := slices.Contains(newIDs, ruleSet.Source)
		hasChanged := !isNew && !bytes.Equal(state[ruleSet.Source], ruleSet.Hash)

		if !isNew && !hasChanged {
			p.l.Debug().
				Str("_bucket", buketID).
				Str("_rule_set", ruleSet.Source).
				Msg("No updates received")

			continue
		}

		var err error

		if isNew {
			err = p.p.OnCreated(ruleSet)
		} else if hasChanged {
			err = p.p.OnUpdated(ruleSet)
		}

		if err != nil {
			return err
		}

		state[ruleSet.Source] = ruleSet.Hash
	}

	return nil
}

func (p *Provider) getBucketState(key string) BucketState {
	value, _ := p.states.LoadOrStore(key, make(BucketState))

	return value.(BucketState) // nolint: forcetypeassert
}

func toRuleSetIDs(ruleSets []*rule_config.RuleSet) []string {
	currentIDs := make([]string, len(ruleSets))

	for idx, ruleSet := range ruleSets {
		currentIDs[idx] = ruleSet.Source
	}

	return currentIDs
}
