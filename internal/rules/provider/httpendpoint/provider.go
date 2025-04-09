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

	"github.com/go-co-op/gocron/v2"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	config2 "github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type Provider struct {
	p          rule.SetProcessor
	l          zerolog.Logger
	s          gocron.Scheduler
	app        app.Context
	cancel     context.CancelFunc
	states     sync.Map
	configured bool
}

func NewProvider(app app.Context, rsp rule.SetProcessor, cch cache.Cache) (*Provider, error) {
	rawConf := app.Config().Providers.HTTPEndpoint
	logger := app.Logger()

	if rawConf == nil {
		return &Provider{}, nil
	}

	type Config struct {
		Endpoints     []*ruleSetEndpoint `mapstructure:"endpoints"      validate:"required,gt=0,dive"`
		WatchInterval *time.Duration     `mapstructure:"watch_interval"`
	}

	var providerConf Config
	if err := decodeConfig(app, rawConf, &providerConf); err != nil {
		return nil, err
	}

	for _, ep := range providerConf.Endpoints {
		ep.init()
	}

	logger = logger.With().Str("_provider_type", "http_endpoint").Logger()
	ctx, cancel := context.WithCancel(
		logger.WithContext(
			cache.WithContext(context.Background(), cch),
		),
	)

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
			"failed creating scheduler for http_endpoint rule provider").CausedBy(err)
	}

	prov := &Provider{
		p:          rsp,
		l:          logger,
		s:          scheduler,
		app:        app,
		cancel:     cancel,
		configured: true,
	}

	for idx, ep := range providerConf.Endpoints {
		var definition gocron.JobDefinition

		if providerConf.WatchInterval != nil && *providerConf.WatchInterval > 0 {
			definition = gocron.DurationJob(*providerConf.WatchInterval)
		} else {
			logger.Info().Msg("Watching of rules is not configured. Updates to rules will have no effect")

			definition = gocron.OneTimeJob(gocron.OneTimeJobStartImmediately())
		}

		if _, err = prov.s.NewJob(definition,
			gocron.NewTask(prov.watchChanges, ep),
			gocron.WithContext(ctx),
		); err != nil {
			return nil, errorchain.NewWithMessagef(heimdall.ErrInternal,
				"failed to create a rule provider worker to fetch rules sets from #%d http_endpoint", idx).
				CausedBy(err)
		}
	}

	logger.Info().Msg("Rule provider configured")

	return prov, nil
}

func (p *Provider) Start(_ context.Context) error {
	if !p.configured {
		return nil
	}

	p.l.Info().Msg("Starting rule provider")

	p.s.Start()

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
	logger := zerolog.Ctx(ctx)
	logger.Debug().
		Str("_endpoint", rsf.ID()).
		Msg("Retrieving rule set")

	ruleSet, err := rsf.FetchRuleSet(ctx, p.app)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			logger.Debug().Msg("Watcher closed")

			return nil
		}

		logger.Warn().Err(err).
			Str("_endpoint", rsf.ID()).
			Msg("Failed to fetch rule set")

		if !errors.Is(err, config2.ErrEmptyRuleSet) &&
			(errors.Is(err, heimdall.ErrInternal) || errors.Is(err, heimdall.ErrConfiguration)) {
			return err
		}

		ruleSet = &config2.RuleSet{
			MetaData: config2.MetaData{
				Source:  "http_endpoint:" + rsf.ID(),
				ModTime: time.Now(),
			},
		}
	}

	if err = p.ruleSetsUpdated(ctx, ruleSet, rsf.ID()); err != nil {
		logger.Warn().Err(err).
			Str("_src", rsf.ID()).
			Msg("Failed to apply rule set changes")
	}

	return nil
}

func (p *Provider) ruleSetsUpdated(ctx context.Context, ruleSet *config2.RuleSet, stateID string) error {
	logger := zerolog.Ctx(ctx)

	var hash []byte

	if value, ok := p.states.Load(stateID); ok { //nolint:nestif
		hash = value.([]byte) // nolint: forcetypeassert

		// rule set was known
		if len(ruleSet.Rules) == 0 {
			// rule set removed
			if err := p.p.OnDeleted(ctx, ruleSet); err != nil {
				return err
			}

			p.states.Delete(stateID)

			return nil
		} else if !bytes.Equal(hash, ruleSet.Hash) {
			// rule set updated
			if err := p.p.OnUpdated(ctx, ruleSet); err != nil {
				return err
			}

			p.states.Store(stateID, ruleSet.Hash)

			return nil
		}
	} else if len(ruleSet.Rules) != 0 {
		// previously unknown rule set
		if err := p.p.OnCreated(ctx, ruleSet); err != nil {
			return err
		}

		p.states.Store(stateID, ruleSet.Hash)

		return nil
	}

	logger.Debug().
		Str("_endpoint", stateID).
		Msg("No updates received")

	return nil
}
