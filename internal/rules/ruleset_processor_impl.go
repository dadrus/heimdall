// Copyright 2022-2025 Dimitrij Drus <dadrus@gmx.de>
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

package rules

import (
	"context"
	"errors"
	"sync"

	"github.com/rs/zerolog"

	config2 "github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/api/v1beta1"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrUnsupportedRuleSetVersion = errors.New("unsupported rule set version")

type ruleSetProcessor struct {
	r  rule.Repository
	f  rule.Factory
	op config2.OperationMode

	sf secrets.ScopedResolverFactory

	scopesMu sync.Mutex
	scopes   map[string]secrets.ScopedResolver
}

func NewRuleSetProcessor(
	op config2.OperationMode,
	repository rule.Repository,
	ruleFactory rule.Factory,
	scopedResolverFactory secrets.ScopedResolverFactory,
) rule.SetProcessor {
	return &ruleSetProcessor{
		r:      repository,
		f:      ruleFactory,
		op:     op,
		sf:     scopedResolverFactory,
		scopes: make(map[string]secrets.ScopedResolver),
	}
}

func (p *ruleSetProcessor) OnCreated(ctx context.Context, ruleSet v1beta1.RuleSet) error {
	logger := zerolog.Ctx(ctx)
	source := rule.RuleSet{
		ID:        ruleSet.ID,
		Name:      ruleSet.Name,
		Provider:  ruleSet.Provider,
		Namespace: ruleSet.Namespace,
	}

	logger.Info().
		Str("_ruleset_id", source.ID).
		Str("_ruleset_name", source.Name).
		Str("_provider", source.Provider).
		Msg("New rule set received")

	if !p.isVersionSupported(ruleSet.Version) {
		return errorchain.NewWithMessage(ErrUnsupportedRuleSetVersion, ruleSet.Version)
	}

	var (
		rules []rule.Rule
		err   error
	)

	resolver, created := p.resolverFor(ruleSet)

	defer func() {
		if created && err != nil {
			p.releaseResolver(ruleSet.ID)
		}
	}()

	if rules, err = p.loadRules(ctx, ruleSet, resolver); err != nil {
		return err
	}

	if p.op == config2.ProxyMode {
		for _, rul := range ruleSet.Rules {
			if rul.Backend.IsInsecure() {
				logger.Warn().
					Str("_ruleset_id", source.ID).
					Str("_ruleset_name", source.Name).
					Str("_provider", source.Provider).
					Str("_rule", rul.ID).
					Msg("Rule contains insecure forward_to configuration")
			}
		}
	}

	err = p.r.AddRuleSet(ctx, source, rules)

	return err
}

func (p *ruleSetProcessor) OnUpdated(ctx context.Context, ruleSet v1beta1.RuleSet) error {
	logger := zerolog.Ctx(ctx)
	source := rule.RuleSet{
		ID:        ruleSet.ID,
		Name:      ruleSet.Name,
		Provider:  ruleSet.Provider,
		Namespace: ruleSet.Namespace,
	}

	logger.Info().
		Str("_ruleset_id", source.ID).
		Str("_ruleset_name", source.Name).
		Str("_provider", source.Provider).
		Msg("RuleSet update received")

	if !p.isVersionSupported(ruleSet.Version) {
		return errorchain.NewWithMessage(ErrUnsupportedRuleSetVersion, ruleSet.Version)
	}

	var (
		rules []rule.Rule
		err   error
	)

	resolver, created := p.resolverFor(ruleSet)
	if created {
		logger.Warn().
			Str("_ruleset_id", source.ID).
			Str("_ruleset_name", source.Name).
			Str("_provider", source.Provider).
			Msg("Got RuleSet update without previously seen the RuleSet. " +
				"This is unexpected and may indicate a bug.")
	}

	defer func() {
		if created && err != nil {
			p.releaseResolver(ruleSet.ID)
		}
	}()

	if rules, err = p.loadRules(ctx, ruleSet, resolver); err != nil {
		return err
	}

	if p.op == config2.ProxyMode {
		for _, rul := range ruleSet.Rules {
			if rul.Backend.IsInsecure() {
				logger.Warn().
					Str("_rule_set", ruleSet.Name).
					Str("_rule", rul.ID).
					Msg("Rule contains insecure forward_to configuration")
			}
		}
	}

	err = p.r.UpdateRuleSet(ctx, source, rules)

	return err
}

func (p *ruleSetProcessor) OnDeleted(ctx context.Context, ruleSet v1beta1.RuleSet) error {
	logger := zerolog.Ctx(ctx)
	source := rule.RuleSet{
		ID:        ruleSet.ID,
		Name:      ruleSet.Name,
		Provider:  ruleSet.Provider,
		Namespace: ruleSet.Namespace,
	}

	logger.Info().
		Str("_ruleset_id", source.ID).
		Str("_ruleset_name", source.Name).
		Str("_provider", source.Provider).
		Msg("Deletion of a rule set received")

	if err := p.r.DeleteRuleSet(ctx, source); err != nil {
		return err
	}

	p.releaseResolver(ruleSet.ID)

	return nil
}

func (p *ruleSetProcessor) isVersionSupported(version string) bool {
	return version == v1beta1.Version
}

func (p *ruleSetProcessor) loadRules(
	ctx context.Context,
	ruleSet v1beta1.RuleSet,
	resolver secrets.Resolver,
) ([]rule.Rule, error) {
	rules := make([]rule.Rule, 0, len(ruleSet.Rules))

	for _, rc := range ruleSet.Rules {
		rul, err := p.f.CreateRule(ctx, resolver, ruleSet, rc)
		if err != nil {
			return nil, errorchain.NewWithMessagef(
				pipeline.ErrInternal,
				"loading rule ID='%s' failed", rc.ID,
			).CausedBy(err)
		}

		rules = append(rules, rul)
	}

	return rules, nil
}

func (p *ruleSetProcessor) resolverFor(ruleSet v1beta1.RuleSet) (secrets.ScopedResolver, bool) {
	p.scopesMu.Lock()
	defer p.scopesMu.Unlock()

	resolver := p.scopes[ruleSet.ID]
	if resolver != nil {
		return resolver, false
	}

	resolver = p.sf.Create(
		ruleSet.ID,
		secrets.WithNamespace(ruleSet.Namespace),
	)

	p.scopes[ruleSet.ID] = resolver

	return resolver, true
}

func (p *ruleSetProcessor) releaseResolver(id string) {
	var resolver secrets.ScopedResolver

	func() {
		p.scopesMu.Lock()
		defer p.scopesMu.Unlock()

		resolver = p.scopes[id]
		if resolver != nil {
			delete(p.scopes, id)
		}
	}()

	if resolver == nil {
		return
	}

	resolver.Release()
}
