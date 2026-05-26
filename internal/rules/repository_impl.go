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
	"context"
	"slices"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/radixtrie"
	"github.com/dadrus/heimdall/internal/x/slicex"
)

type ruleSetMetrics struct {
	rulesCount int64
	attrs      attribute.Set
}

type ruleSetID struct {
	id       string
	provider string
}

type repository struct {
	dr rule.Rule

	knownRules       []rule.Rule
	ruleSetsMetaInfo map[ruleSetID]ruleSetMetrics
	knownRulesMutex  sync.RWMutex

	index          *radixtrie.Trie[rule.Route]
	rulesTrieMutex sync.RWMutex

	rl metric.Int64ObservableGauge
}

func newRepository(ruleFactory rule.Factory, meter metric.Meter) (rule.Repository, error) {
	gauge, err := meter.Int64ObservableGauge("rules.loaded",
		metric.WithDescription("Number of loaded rules"),
		metric.WithUnit("{rule}"),
	)
	if err != nil {
		return nil, errorchain.NewWithMessagef(pipeline.ErrInternal,
			"failed creating rules.loaded gauge").CausedBy(err)
	}

	repo := &repository{
		dr: x.IfThenElseExec(ruleFactory.HasDefaultRule(),
			func() rule.Rule { return ruleFactory.DefaultRule() },
			func() rule.Rule { return nil }),
		index: radixtrie.New[rule.Route](
			radixtrie.WithValuesConstraints(func(oldValues []rule.Route, newValue rule.Route) bool {
				// only rules from the same rule set can be placed in one node
				return len(oldValues) == 0 || oldValues[0].Rule().Source().Equals(newValue.Rule().Source())
			}),
		),
		rl:               gauge,
		ruleSetsMetaInfo: make(map[ruleSetID]ruleSetMetrics, 10),
	}

	if _, err = meter.RegisterCallback(repo.collectMetrics, gauge); err != nil {
		return nil, errorchain.NewWithMessagef(pipeline.ErrInternal,
			"failed registering callback for metrics collection").CausedBy(err)
	}

	return repo, nil
}

func (r *repository) FindRule(ctx pipeline.Context) (rule.Rule, error) {
	request := ctx.Request()

	r.rulesTrieMutex.RLock()
	defer r.rulesTrieMutex.RUnlock()

	entry, err := r.index.FindEntry(
		request.URL.Host,
		x.IfThenElse(len(request.URL.RawPath) != 0, request.URL.RawPath, request.URL.Path),
		radixtrie.LookupMatcherFunc[rule.Route](func(route rule.Route, keys, values []string) bool {
			return route.Matches(ctx, keys, values)
		}),
	)
	if err != nil {
		if r.dr != nil {
			return r.dr, nil
		}

		return nil, errorchain.NewWithMessagef(pipeline.ErrNoRuleFound,
			"no applicable rule found for %s", request.URL.String())
	}

	request.URL.Captures = entry.Parameters

	return entry.Value.Rule(), nil
}

func (r *repository) AddRuleSet(_ context.Context, _ rule.RuleSet, rules []rule.Rule) error {
	r.knownRulesMutex.Lock()
	defer r.knownRulesMutex.Unlock()

	// Check if the rules from the new rule set define more generic routes for
	// already existing ones. If so, reject them

	// create a trie containing only the new rules
	tmp := radixtrie.New[rule.Route](
		radixtrie.WithValuesConstraints(func(oldValues []rule.Route, newValue rule.Route) bool {
			// only rules from the same rule set can be placed in one node
			return len(oldValues) == 0 || oldValues[0].Rule().Source().Equals(newValue.Rule().Source())
		}))
	if err := r.addRulesTo(tmp, rules); err != nil {
		return err
	}

	// Check if adding existing rules would result in the violation of the constraint, that
	// more specific and more generic rules must be defined in the same rule set
	if err := r.addRulesTo(tmp, r.knownRules); err != nil {
		return err
	}

	// Try adding the new rules into the existing index now.
	tmp = r.index.Clone()

	if err := r.addRulesTo(tmp, rules); err != nil {
		return err
	}

	r.knownRules = append(r.knownRules, rules...)

	r.prepareMetrics()

	r.rulesTrieMutex.Lock()
	r.index = tmp
	r.rulesTrieMutex.Unlock()

	return nil
}

func (r *repository) UpdateRuleSet(_ context.Context, src rule.RuleSet, rules []rule.Rule) error {
	// create rules
	r.knownRulesMutex.Lock()
	defer r.knownRulesMutex.Unlock()

	// find all rules for the given src id
	applicable := slicex.Filter(r.knownRules, func(r rule.Rule) bool { return r.Source().Equals(src) })

	// find new rules, as well as those, which have been changed.
	toBeAdded := slicex.Filter(rules, func(newRule rule.Rule) bool {
		ruleIsNew := !slices.ContainsFunc(applicable, func(existingRule rule.Rule) bool {
			return existingRule.SameAs(newRule)
		})

		ruleChanged := slices.ContainsFunc(applicable, func(existingRule rule.Rule) bool {
			return existingRule.SameAs(newRule) && !existingRule.Equals(newRule)
		})

		return ruleIsNew || ruleChanged
	})

	// find deleted rules, as well as those, which have been changed.
	toBeDeleted := slicex.Filter(applicable, func(existingRule rule.Rule) bool {
		ruleGone := !slices.ContainsFunc(rules, func(newRule rule.Rule) bool {
			return newRule.SameAs(existingRule)
		})

		ruleChanged := slices.ContainsFunc(rules, func(newRule rule.Rule) bool {
			return newRule.SameAs(existingRule) && !newRule.Equals(existingRule)
		})

		return ruleGone || ruleChanged
	})

	// prepare the new set of known rules, which does not contain the rules, which are gone
	// with the update
	knownRules := slices.DeleteFunc(slices.Clone(r.knownRules), func(loaded rule.Rule) bool {
		return slices.Contains(toBeDeleted, loaded)
	})

	// Check if the to be added rules define more generic routes for already existing ones.
	// If so, reject them

	// create a trie containing only the new rules
	tmp := radixtrie.New[rule.Route](
		radixtrie.WithValuesConstraints(func(oldValues []rule.Route, newValue rule.Route) bool {
			// only rules from the same rule set can be placed in one node
			return len(oldValues) == 0 || oldValues[0].Rule().Source().Equals(newValue.Rule().Source())
		}))
	if err := r.addRulesTo(tmp, toBeAdded); err != nil {
		return err
	}

	// Check if adding existing rules would result in the violation of the constraint, that
	// more specific and more generic rules must be defined in the same rule set
	if err := r.addRulesTo(tmp, knownRules); err != nil {
		return err
	}

	// Try updating the existing index now.
	tmp = r.index.Clone()

	// delete rules
	if err := r.removeRulesFrom(tmp, toBeDeleted); err != nil {
		return err
	}

	// add rules
	if err := r.addRulesTo(tmp, toBeAdded); err != nil {
		return err
	}

	knownRules = append(knownRules, toBeAdded...)
	r.knownRules = knownRules

	r.prepareMetrics()

	r.rulesTrieMutex.Lock()
	r.index = tmp
	r.rulesTrieMutex.Unlock()

	return nil
}

func (r *repository) DeleteRuleSet(_ context.Context, src rule.RuleSet) error {
	r.knownRulesMutex.Lock()
	defer r.knownRulesMutex.Unlock()

	// find all rules for the given src id
	applicable := slicex.Filter(r.knownRules, func(r rule.Rule) bool { return r.Source().Equals(src) })

	tmp := r.index.Clone()

	// remove them
	if err := r.removeRulesFrom(tmp, applicable); err != nil {
		return err
	}

	r.knownRules = slices.DeleteFunc(r.knownRules, func(r rule.Rule) bool {
		return slices.Contains(applicable, r)
	})

	r.prepareMetrics()

	r.rulesTrieMutex.Lock()
	r.index = tmp
	r.rulesTrieMutex.Unlock()

	return nil
}

func (r *repository) prepareMetrics() {
	clear(r.ruleSetsMetaInfo)

	for _, rul := range r.knownRules {
		src := rul.Source()
		key := ruleSetID{
			id:       src.ID,
			provider: src.Provider,
		}

		metrics, ok := r.ruleSetsMetaInfo[key]
		if !ok {
			metrics.attrs = attribute.NewSet(
				ruleSetIDKey.String(src.ID),
				ruleSetNameKey.String(src.Name),
				ruleSetProviderKey.String(src.Provider),
			)
		}

		metrics.rulesCount++
		r.ruleSetsMetaInfo[key] = metrics
	}
}

func (r *repository) addRulesTo(trie *radixtrie.Trie[rule.Route], rules []rule.Rule) error {
	for _, rul := range rules {
		for _, route := range rul.Routes() {
			src := rul.Source()
			path := route.Path()
			host := route.Host()

			entry, _ := trie.FindEntry(
				host,
				path,
				radixtrie.LookupMatcherFunc[rule.Route](func(route rule.Route, _, _ []string) bool {
					return !route.Rule().Source().Equals(src)
				}),
			)
			if entry != nil {
				return errorchain.NewWithMessagef(pipeline.ErrConfiguration,
					"conflicting rules: %s from %s and %s from %s",
					rul.ID(), rul.Source(), entry.Value.Rule().ID(), entry.Value.Rule().Source())
			}

			nodes, _ := trie.Lookup(host, "", radixtrie.WithWildcardMatch[rule.Route]())
			for _, node := range nodes {
				entry, _ = node.FindEntry(
					"",
					path,
					radixtrie.LookupMatcherFunc[rule.Route](func(route rule.Route, _, _ []string) bool {
						return !route.Rule().Source().Equals(src)
					}),
				)
				if entry != nil {
					return errorchain.NewWithMessagef(pipeline.ErrConfiguration,
						"conflicting rules: %s from %s and %s from %s",
						rul.ID(), src, entry.Value.Rule().ID(), entry.Value.Rule().Source())
				}
			}

			if err := trie.Add(host, path, route); err != nil {
				return errorchain.NewWithMessagef(pipeline.ErrInternal,
					"failed adding rule %s from %s", rul.ID(), src).
					CausedBy(err)
			}
		}
	}

	return nil
}

func (r *repository) removeRulesFrom(trie *radixtrie.Trie[rule.Route], tbdRules []rule.Rule) error {
	for _, rul := range tbdRules {
		for _, route := range rul.Routes() {
			if err := trie.Delete(
				route.Host(),
				route.Path(),
				radixtrie.ValueMatcherFunc[rule.Route](func(route rule.Route) bool {
					return route.Rule().SameAs(rul)
				}),
			); err != nil {
				return errorchain.NewWithMessagef(pipeline.ErrInternal,
					"failed deleting rule %s from %s", rul.ID(), rul.Source()).
					CausedBy(err)
			}
		}
	}

	return nil
}

func (r *repository) collectMetrics(_ context.Context, observer metric.Observer) error {
	r.knownRulesMutex.RLock()
	defer r.knownRulesMutex.RUnlock()

	for _, metrics := range r.ruleSetsMetaInfo {
		observer.ObserveInt64(r.rl, metrics.rulesCount, metric.WithAttributeSet(metrics.attrs))
	}

	return nil
}
