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

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrUnsupportedRuleSetVersion = errors.New("unsupported rule set version")

type ruleSetProcessor struct {
	r rule.Repository
	f rule.Factory
}

func NewRuleSetProcessor(repository rule.Repository, factory rule.Factory) rule.SetProcessor {
	return &ruleSetProcessor{
		r: repository,
		f: factory,
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
			return nil, errorchain.NewWithMessagef(heimdall.ErrInternal,
				"loading rule ID='%s' failed", rc.ID).CausedBy(err)
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

	return p.r.AddRuleSet(ruleSet.Source, rules)
}

func (p *ruleSetProcessor) OnUpdated(ruleSet *config.RuleSet) error {
	if !p.isVersionSupported(ruleSet.Version) {
		return errorchain.NewWithMessage(ErrUnsupportedRuleSetVersion, ruleSet.Version)
	}

	rules, err := p.loadRules(ruleSet)
	if err != nil {
		return err
	}

	return p.r.UpdateRuleSet(ruleSet.Source, rules)
}

func (p *ruleSetProcessor) OnDeleted(ruleSet *config.RuleSet) error {
	return p.r.DeleteRuleSet(ruleSet.Source)
}
