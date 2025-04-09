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

	"github.com/rs/zerolog"

	config2 "github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrUnsupportedRuleSetVersion = errors.New("unsupported rule set version")

type ruleSetProcessor struct {
	r  rule.Repository
	f  rule.Factory
	op config2.OperationMode
}

func NewRuleSetProcessor(repository rule.Repository, factory rule.Factory, op config2.OperationMode) rule.SetProcessor {
	return &ruleSetProcessor{
		r:  repository,
		f:  factory,
		op: op,
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

func (p *ruleSetProcessor) OnCreated(ctx context.Context, ruleSet *config.RuleSet) error {
	logger := zerolog.Ctx(ctx)
	logger.Info().Str("_rule_set", ruleSet.Name).Msg("New rule set received")

	if !p.isVersionSupported(ruleSet.Version) {
		return errorchain.NewWithMessage(ErrUnsupportedRuleSetVersion, ruleSet.Version)
	}

	rules, err := p.loadRules(ruleSet)
	if err != nil {
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

	return p.r.AddRuleSet(ctx, ruleSet.Source, rules)
}

func (p *ruleSetProcessor) OnUpdated(ctx context.Context, ruleSet *config.RuleSet) error {
	logger := zerolog.Ctx(ctx)
	logger.Info().Str("_rule_set", ruleSet.Name).Msg("Update of a rule set received")

	if !p.isVersionSupported(ruleSet.Version) {
		return errorchain.NewWithMessage(ErrUnsupportedRuleSetVersion, ruleSet.Version)
	}

	rules, err := p.loadRules(ruleSet)
	if err != nil {
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

	return p.r.UpdateRuleSet(ctx, ruleSet.Source, rules)
}

func (p *ruleSetProcessor) OnDeleted(ctx context.Context, ruleSet *config.RuleSet) error {
	logger := zerolog.Ctx(ctx)
	logger.Info().Str("_rule_set", ruleSet.Name).Msg("Deletion of a rule set received")

	return p.r.DeleteRuleSet(ctx, ruleSet.Source)
}
