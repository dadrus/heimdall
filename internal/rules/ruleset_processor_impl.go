// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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
	"errors"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrUnsupportedRuleSetVersion = errors.New("unsupported rule set version")

type ruleSetProcessor struct {
	q event.RuleSetChangedEventQueue
	f rule.Factory
	l zerolog.Logger
}

func NewRuleSetProcessor(
	queue event.RuleSetChangedEventQueue, factory rule.Factory, logger zerolog.Logger,
) rule.SetProcessor {
	return &ruleSetProcessor{
		q: queue,
		f: factory,
		l: logger,
	}
}

func (p *ruleSetProcessor) isVersionSupported(version string) bool {
	return version == config.CurrentRuleSetVersion
}

func (p *ruleSetProcessor) loadRules(ruleSet *config.RuleSet) ([]rule.Rule, error) {
	rules := make([]rule.Rule, len(ruleSet.Rules))

	for idx, rc := range ruleSet.Rules {
		rul, err := p.f.CreateRule(ruleSet.Version, ruleSet.Source, rc)
		if err != nil {
			return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed loading rule").CausedBy(err)
		}

		rules[idx] = rul
	}

	return rules, nil
}

func (p *ruleSetProcessor) OnCreated(ruleSet *config.RuleSet) error {
	if !p.isVersionSupported(ruleSet.Version) {
		return errorchain.NewWithMessage(ErrUnsupportedRuleSetVersion, ruleSet.Version)
	}

	rules, err := p.loadRules(ruleSet)
	if err != nil {
		return err
	}

	evt := event.RuleSetChanged{
		Source:     ruleSet.Source,
		Name:       ruleSet.Name,
		Rules:      rules,
		ChangeType: event.Create,
	}

	p.sendEvent(evt)

	return nil
}

func (p *ruleSetProcessor) OnUpdated(ruleSet *config.RuleSet) error {
	if !p.isVersionSupported(ruleSet.Version) {
		return errorchain.NewWithMessage(ErrUnsupportedRuleSetVersion, ruleSet.Version)
	}

	rules, err := p.loadRules(ruleSet)
	if err != nil {
		return err
	}

	evt := event.RuleSetChanged{
		Source:     ruleSet.Source,
		Name:       ruleSet.Name,
		Rules:      rules,
		ChangeType: event.Update,
	}

	p.sendEvent(evt)

	return nil
}

func (p *ruleSetProcessor) OnDeleted(ruleSet *config.RuleSet) error {
	evt := event.RuleSetChanged{
		Source:     ruleSet.Source,
		Name:       ruleSet.Name,
		ChangeType: event.Remove,
	}

	p.sendEvent(evt)

	return nil
}

func (p *ruleSetProcessor) sendEvent(evt event.RuleSetChanged) {
	p.l.Info().
		Str("_src", evt.Source).
		Str("_type", evt.ChangeType.String()).
		Msg("Rule set changed")
	p.q <- evt
}
