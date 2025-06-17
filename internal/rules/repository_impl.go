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

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/radixtrie"
	"github.com/dadrus/heimdall/internal/x/slicex"
)

type repository struct {
	dr rule.Rule

	knownRules      []rule.Rule
	knownRulesMutex sync.Mutex

	index          *radixtrie.Trie[rule.Route]
	rulesTrieMutex sync.RWMutex
}

func newRepository(ruleFactory rule.Factory) rule.Repository {
	return &repository{
		dr: x.IfThenElseExec(ruleFactory.HasDefaultRule(),
			func() rule.Rule { return ruleFactory.DefaultRule() },
			func() rule.Rule { return nil }),
		index: radixtrie.New[rule.Route](
			radixtrie.WithValuesConstraints(func(oldValues []rule.Route, newValue rule.Route) bool {
				// only rules from the same rule set can be placed in one node
				return len(oldValues) == 0 || oldValues[0].Rule().SrcID() == newValue.Rule().SrcID()
			}),
		),
	}
}

func (r *repository) FindRule(ctx heimdall.RequestContext) (rule.Rule, error) {
	request := ctx.Request()

	r.rulesTrieMutex.RLock()
	defer r.rulesTrieMutex.RUnlock()

	entry, err := r.index.Find(
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

		return nil, errorchain.NewWithMessagef(heimdall.ErrNoRuleFound,
			"no applicable rule found for %s", request.URL.String())
	}

	request.URL.Captures = entry.Parameters

	return entry.Value.Rule(), nil
}

func (r *repository) AddRuleSet(_ context.Context, _ string, rules []rule.Rule) error {
	r.knownRulesMutex.Lock()
	defer r.knownRulesMutex.Unlock()

	// Check if the rules from the new rule set define more generic routes for
	// already existing ones. If so, reject them

	// create a trie containing only the new rules
	tmp := radixtrie.New[rule.Route](
		radixtrie.WithValuesConstraints(func(oldValues []rule.Route, newValue rule.Route) bool {
			// only rules from the same rule set can be placed in one node
			return len(oldValues) == 0 || oldValues[0].Rule().SrcID() == newValue.Rule().SrcID()
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

	r.rulesTrieMutex.Lock()
	r.index = tmp
	r.rulesTrieMutex.Unlock()

	return nil
}

func (r *repository) UpdateRuleSet(_ context.Context, srcID string, rules []rule.Rule) error {
	// create rules
	r.knownRulesMutex.Lock()
	defer r.knownRulesMutex.Unlock()

	// find all rules for the given src id
	applicable := slicex.Filter(r.knownRules, func(r rule.Rule) bool { return r.SrcID() == srcID })

	// find new rules, as well as those, which have been changed.
	toBeAdded := slicex.Filter(rules, func(newRule rule.Rule) bool {
		ruleIsNew := !slices.ContainsFunc(applicable, func(existingRule rule.Rule) bool {
			return existingRule.SameAs(newRule)
		})

		ruleChanged := slices.ContainsFunc(applicable, func(existingRule rule.Rule) bool {
			return existingRule.SameAs(newRule) && !existingRule.EqualTo(newRule)
		})

		return ruleIsNew || ruleChanged
	})

	// find deleted rules, as well as those, which have been changed.
	toBeDeleted := slicex.Filter(applicable, func(existingRule rule.Rule) bool {
		ruleGone := !slices.ContainsFunc(rules, func(newRule rule.Rule) bool {
			return newRule.SameAs(existingRule)
		})

		ruleChanged := slices.ContainsFunc(rules, func(newRule rule.Rule) bool {
			return newRule.SameAs(existingRule) && !newRule.EqualTo(existingRule)
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
			return len(oldValues) == 0 || oldValues[0].Rule().SrcID() == newValue.Rule().SrcID()
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

	r.rulesTrieMutex.Lock()
	r.index = tmp
	r.rulesTrieMutex.Unlock()

	return nil
}

func (r *repository) DeleteRuleSet(_ context.Context, srcID string) error {
	r.knownRulesMutex.Lock()
	defer r.knownRulesMutex.Unlock()

	// find all rules for the given src id
	applicable := slicex.Filter(r.knownRules, func(r rule.Rule) bool { return r.SrcID() == srcID })

	tmp := r.index.Clone()

	// remove them
	if err := r.removeRulesFrom(tmp, applicable); err != nil {
		return err
	}

	r.knownRules = slices.DeleteFunc(r.knownRules, func(r rule.Rule) bool {
		return slices.Contains(applicable, r)
	})

	r.rulesTrieMutex.Lock()
	r.index = tmp
	r.rulesTrieMutex.Unlock()

	return nil
}

func (r *repository) addRulesTo(trie *radixtrie.Trie[rule.Route], rules []rule.Rule) error {
	for _, rul := range rules {
		for _, route := range rul.Routes() {
			srcID := rul.SrcID()
			path := route.Path()
			host := route.Host()

			entry, _ := trie.Find(
				host,
				path,
				radixtrie.LookupMatcherFunc[rule.Route](func(route rule.Route, _, _ []string) bool {
					return route.Rule().SrcID() != srcID
				}),
			)
			if entry != nil {
				return errorchain.NewWithMessagef(heimdall.ErrConfiguration,
					"rule %s from %s conflicts with rule %s from %s",
					rul.ID(), srcID, entry.Value.Rule().ID(), entry.Value.Rule().SrcID())
			}

			if err := trie.Add(
				host,
				path,
				route,
				radixtrie.WithBacktracking[rule.Route](rul.AllowsBacktracking()),
			); err != nil {
				return errorchain.NewWithMessagef(heimdall.ErrInternal,
					"failed adding rule %s from %s", rul.ID(), srcID).
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
				return errorchain.NewWithMessagef(heimdall.ErrInternal,
					"failed deleting rule %s from %s", rul.ID(), rul.SrcID()).
					CausedBy(err)
			}
		}
	}

	return nil
}
