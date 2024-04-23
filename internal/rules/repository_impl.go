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
	"bytes"
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

	index          *radixtree.Tree[rule.Rule]
	rulesTreeMutex sync.RWMutex
}

func newRepository(ruleFactory rule.Factory) rule.Repository {
	return &repository{
		dr: x.IfThenElseExec(ruleFactory.HasDefaultRule(),
			func() rule.Rule { return ruleFactory.DefaultRule() },
			func() rule.Rule { return nil }),
		index: radixtree.New[rule.Rule](
			radixtree.WithValuesConstraints(func(oldValues []rule.Rule, newValue rule.Rule) bool {
				// only rules from the same rule set can be placed in one node
				return len(oldValues) == 0 || oldValues[0].SrcID() == newValue.SrcID()
			}),
		),
	}
}

func (r *repository) FindRule(ctx heimdall.Context) (rule.Rule, error) {
	request := ctx.Request()

	r.rulesTreeMutex.RLock()
	defer r.rulesTreeMutex.RUnlock()

	entry, err := r.index.Find(
		x.IfThenElse(len(request.URL.RawPath) != 0, request.URL.RawPath, request.URL.Path),
		radixtree.MatcherFunc[rule.Rule](func(candidate rule.Rule) bool { return candidate.Matches(ctx) }),
	)
	if err != nil {
		if r.dr != nil {
			return r.dr, nil
		}

		return nil, errorchain.NewWithMessagef(heimdall.ErrNoRuleFound,
			"no applicable rule found for %s", request.URL.String())
	}

	request.URL.Captures = entry.Parameters

	return entry.Value, nil
}

func (r *repository) AddRuleSet(_ string, rules []rule.Rule) error {
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

func (r *repository) UpdateRuleSet(srcID string, rules []rule.Rule) error {
	// create rules
	r.knownRulesMutex.Lock()
	defer r.knownRulesMutex.Unlock()

	// find all rules for the given src id
	applicable := slicex.Filter(r.knownRules, func(r rule.Rule) bool { return r.SrcID() == srcID })

	// find new rules - these are completely new ones, as well as those, which have their path expressions
	// updated, so that the old ones must be removed and the updated ones must be inserted into the tree.
	newRules := slicex.Filter(rules, func(newRule rule.Rule) bool {
		ruleIsNew := !slices.ContainsFunc(applicable, func(existingRule rule.Rule) bool {
			return existingRule.ID() == newRule.ID()
		})

		pathExpressionChanged := slices.ContainsFunc(applicable, func(existingRule rule.Rule) bool {
			return existingRule.ID() == newRule.ID() && existingRule.PathExpression() != newRule.PathExpression()
		})

		return ruleIsNew || pathExpressionChanged
	})

	// find updated rules - those, which have the same ID and same path expression. These can be just updated
	// in the tree without the need to remove the old ones first and insert the updated ones afterward.
	updatedRules := slicex.Filter(rules, func(r rule.Rule) bool {
		loaded := r.(*ruleImpl) // nolint: forcetypeassert

		return slices.ContainsFunc(applicable, func(existing rule.Rule) bool {
			known := existing.(*ruleImpl) // nolint: forcetypeassert

			return known.id == loaded.id && // same id
				!bytes.Equal(known.hash, loaded.hash) && // different hash
				known.pathExpression == loaded.pathExpression // same path expressions
		})
	})

	// find deleted rules - those, which are gone, or still present, but have a different path
	// expression. Latter means, the old ones needs to be removed and the updated ones inserted
	deletedRules := slicex.Filter(applicable, func(existingRule rule.Rule) bool {
		ruleGone := !slices.ContainsFunc(rules, func(newRule rule.Rule) bool {
			return newRule.ID() == existingRule.ID()
		})

		pathExpressionChanged := slices.ContainsFunc(rules, func(newRule rule.Rule) bool {
			return existingRule.ID() == newRule.ID() && existingRule.PathExpression() != newRule.PathExpression()
		})

		return ruleGone || pathExpressionChanged
	})

	tmp := r.index.Clone()

	// remove deleted rules
	if err := r.removeRulesFrom(tmp, deletedRules); err != nil {
		return err
	}

	// replace updated rules
	if err := r.replaceRulesIn(tmp, updatedRules); err != nil {
		return err
	}

	// add new rules
	if err := r.addRulesTo(tmp, newRules); err != nil {
		return err
	}

	r.knownRules = slices.DeleteFunc(r.knownRules, func(loaded rule.Rule) bool {
		return slices.Contains(deletedRules, loaded)
	})

	for idx, existing := range r.knownRules {
		for _, updated := range updatedRules {
			if updated.SameAs(existing) {
				r.knownRules[idx] = updated

				break
			}
		}
	}

	r.knownRules = append(r.knownRules, newRules...)

	r.rulesTreeMutex.Lock()
	r.index = tmp
	r.rulesTreeMutex.Unlock()

	return nil
}

func (r *repository) DeleteRuleSet(srcID string) error {
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

func (r *repository) addRulesTo(tree *radixtree.Tree[rule.Rule], rules []rule.Rule) error {
	for _, rul := range rules {
		if err := tree.Add(rul.PathExpression(), rul); err != nil {
			return errorchain.NewWithMessagef(heimdall.ErrInternal, "failed adding rule ID='%s'", rul.ID()).
				CausedBy(err)
		}
	}

	return nil
}

func (r *repository) removeRulesFrom(tree *radixtree.Tree[rule.Rule], tbdRules []rule.Rule) error {
	for _, rul := range tbdRules {
		if err := tree.Delete(
			rul.PathExpression(),
			radixtree.MatcherFunc[rule.Rule](func(existing rule.Rule) bool { return existing.SameAs(rul) }),
		); err != nil {
			return errorchain.NewWithMessagef(heimdall.ErrInternal, "failed deleting rule ID='%s'", rul.ID()).
				CausedBy(err)
		}
	}

	return nil
}

func (r *repository) replaceRulesIn(tree *radixtree.Tree[rule.Rule], rules []rule.Rule) error {
	for _, updated := range rules {
		if err := tree.Update(
			updated.PathExpression(),
			updated,
			radixtree.MatcherFunc[rule.Rule](func(existing rule.Rule) bool {
				return existing.SameAs(updated)
			}),
		); err != nil {
			return errorchain.NewWithMessagef(heimdall.ErrInternal, "failed replacing rule ID='%s'", updated.ID()).
				CausedBy(err)
		}
	}

	return nil
}
