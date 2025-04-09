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
	"github.com/dadrus/heimdall/internal/x/radixtree"
	"github.com/dadrus/heimdall/internal/x/slicex"
)

type repository struct {
	dr rule.Rule

	knownRules      []rule.Rule
	knownRulesMutex sync.Mutex

	index          *radixtree.Tree[rule.Route]
	rulesTreeMutex sync.RWMutex
}

func newRepository(ruleFactory rule.Factory) rule.Repository {
	return &repository{
		dr: x.IfThenElseExec(ruleFactory.HasDefaultRule(),
			func() rule.Rule { return ruleFactory.DefaultRule() },
			func() rule.Rule { return nil }),
		index: radixtree.New[rule.Route](
			radixtree.WithValuesConstraints(func(oldValues []rule.Route, newValue rule.Route) bool {
				// only rules from the same rule set can be placed in one node
				return len(oldValues) == 0 || oldValues[0].Rule().SrcID() == newValue.Rule().SrcID()
			}),
		),
	}
}

func (r *repository) FindRule(ctx heimdall.RequestContext) (rule.Rule, error) {
	request := ctx.Request()

	r.rulesTreeMutex.RLock()
	defer r.rulesTreeMutex.RUnlock()

	entry, err := r.index.Find(
		x.IfThenElse(len(request.URL.RawPath) != 0, request.URL.RawPath, request.URL.Path),
		radixtree.LookupMatcherFunc[rule.Route](func(route rule.Route, keys, values []string) bool {
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

	tmp := r.index.Clone()

	if err := r.addRulesTo(tmp, rules); err != nil {
		return err
	}

	r.knownRules = append(r.knownRules, rules...)

	r.rulesTreeMutex.Lock()
	r.index = tmp
	r.rulesTreeMutex.Unlock()

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

	tmp := r.index.Clone()

	// delete rules
	if err := r.removeRulesFrom(tmp, toBeDeleted); err != nil {
		return err
	}

	// add rules
	if err := r.addRulesTo(tmp, toBeAdded); err != nil {
		return err
	}

	r.knownRules = slices.DeleteFunc(r.knownRules, func(loaded rule.Rule) bool {
		return slices.Contains(toBeDeleted, loaded)
	})
	r.knownRules = append(r.knownRules, toBeAdded...)

	r.rulesTreeMutex.Lock()
	r.index = tmp
	r.rulesTreeMutex.Unlock()

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

	r.rulesTreeMutex.Lock()
	r.index = tmp
	r.rulesTreeMutex.Unlock()

	return nil
}

func (r *repository) addRulesTo(tree *radixtree.Tree[rule.Route], rules []rule.Rule) error {
	for _, rul := range rules {
		for _, route := range rul.Routes() {
			if err := tree.Add(
				route.Path(),
				route,
				radixtree.WithBacktracking[rule.Route](rul.AllowsBacktracking()),
			); err != nil {
				return errorchain.NewWithMessagef(heimdall.ErrInternal, "failed adding rule ID='%s'", rul.ID()).
					CausedBy(err)
			}
		}
	}

	return nil
}

func (r *repository) removeRulesFrom(tree *radixtree.Tree[rule.Route], tbdRules []rule.Rule) error {
	for _, rul := range tbdRules {
		for _, route := range rul.Routes() {
			if err := tree.Delete(
				route.Path(),
				radixtree.ValueMatcherFunc[rule.Route](func(route rule.Route) bool {
					return route.Rule().SameAs(rul)
				}),
			); err != nil {
				return errorchain.NewWithMessagef(heimdall.ErrInternal, "failed deleting rule ID='%s'", rul.ID()).
					CausedBy(err)
			}
		}
	}

	return nil
}
