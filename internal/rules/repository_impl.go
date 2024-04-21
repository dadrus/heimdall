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
	"context"
	"slices"
	"sync"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/radixtree"
	"github.com/dadrus/heimdall/internal/x/slicex"
)

func newRepository(
	queue event.RuleSetChangedEventQueue,
	ruleFactory rule.Factory,
	logger zerolog.Logger,
) *repository {
	return &repository{
		dr: x.IfThenElseExec(ruleFactory.HasDefaultRule(),
			func() rule.Rule { return ruleFactory.DefaultRule() },
			func() rule.Rule { return nil }),
		logger:    logger,
		queue:     queue,
		quit:      make(chan bool),
		rulesTree: radixtree.New[rule.Rule](),
	}
}

type repository struct {
	dr     rule.Rule
	logger zerolog.Logger

	knownRules []rule.Rule

	rulesTree radixtree.Tree[rule.Rule]
	mutex     sync.RWMutex

	queue event.RuleSetChangedEventQueue
	quit  chan bool
}

func (r *repository) FindRule(ctx heimdall.Context) (rule.Rule, error) {
	request := ctx.Request()

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	entry, err := r.rulesTree.Find(
		request.URL.Path,
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

func (r *repository) Start(_ context.Context) error {
	r.logger.Info().Msg("Starting rule definition loader")

	go r.watchRuleSetChanges()

	return nil
}

func (r *repository) Stop(_ context.Context) error {
	r.logger.Info().Msg("Tearing down rule definition loader")

	r.quit <- true

	close(r.quit)

	return nil
}

func (r *repository) watchRuleSetChanges() {
	for {
		select {
		case evt, ok := <-r.queue:
			if !ok {
				r.logger.Debug().Msg("Rule set definition queue closed")
			}

			switch evt.ChangeType {
			case event.Create:
				r.addRuleSet(evt.Source, evt.Rules)
			case event.Update:
				r.updateRuleSet(evt.Source, evt.Rules)
			case event.Remove:
				r.deleteRuleSet(evt.Source)
			}
		case <-r.quit:
			r.logger.Info().Msg("Rule definition loader stopped")

			return
		}
	}
}

func (r *repository) addRuleSet(srcID string, rules []rule.Rule) {
	r.logger.Info().Str("_src", srcID).Msg("Adding rule set")

	// add them
	r.addRules(rules)
}

func (r *repository) updateRuleSet(srcID string, rules []rule.Rule) {
	// create rules
	r.logger.Info().Str("_src", srcID).Msg("Updating rule set")

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
	// in the tree without the need to remove the old ones first and insert the updated ones afterwards.
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

	// remove deleted rules
	r.removeRules(deletedRules)

	// replace updated rules
	r.replaceRules(updatedRules)

	// add new rules
	r.addRules(newRules)
}

func (r *repository) deleteRuleSet(srcID string) {
	r.logger.Info().Str("_src", srcID).Msg("Deleting rule set")

	// find all rules for the given src id
	applicable := slicex.Filter(r.knownRules, func(r rule.Rule) bool { return r.SrcID() == srcID })

	// remove them
	r.removeRules(applicable)
}

func (r *repository) addRules(rules []rule.Rule) {
	for _, rul := range rules {
		r.mutex.Lock()
		err := r.rulesTree.Add(rul.PathExpression(), rul)
		r.mutex.Unlock()

		if err != nil {
			r.logger.Error().Err(err).
				Str("_src", rul.SrcID()).
				Str("_id", rul.ID()).
				Msg("Failed to add rule")
		} else {
			r.logger.Debug().
				Str("_src", rul.SrcID()).
				Str("_id", rul.ID()).
				Msg("Rule added")

			r.knownRules = append(r.knownRules, rul)
		}
	}
}

func (r *repository) removeRules(tbdRules []rule.Rule) {
	var failed []rule.Rule

	for _, rul := range tbdRules {
		r.mutex.Lock()
		err := r.rulesTree.Delete(
			rul.PathExpression(),
			radixtree.MatcherFunc[rule.Rule](func(existing rule.Rule) bool { return existing.SameAs(rul) }),
		)
		r.mutex.Unlock()

		if err != nil {
			r.logger.Error().Err(err).
				Str("_src", rul.SrcID()).
				Str("_id", rul.ID()).
				Msg("Failed to remove rule. Please file a bug report!")

			failed = append(failed, rul)
		} else {
			r.logger.Debug().
				Str("_src", rul.SrcID()).
				Str("_id", rul.ID()).
				Msg("Rule removed")
		}
	}

	r.knownRules = slices.DeleteFunc(r.knownRules, func(r rule.Rule) bool {
		return !slices.Contains(failed, r) && slices.Contains(tbdRules, r)
	})
}

func (r *repository) replaceRules(rules []rule.Rule) {
	var failed []rule.Rule

	for _, updated := range rules {
		r.mutex.Lock()
		err := r.rulesTree.Update(
			updated.PathExpression(),
			updated,
			radixtree.MatcherFunc[rule.Rule](func(existing rule.Rule) bool { return existing.SameAs(updated) }),
		)
		r.mutex.Unlock()

		if err != nil {
			r.logger.Error().Err(err).
				Str("_src", updated.SrcID()).
				Str("_id", updated.ID()).
				Msg("Failed to replace rule. Please file a bug report!")

			failed = append(failed, updated)
		} else {
			r.logger.Debug().
				Str("_src", updated.SrcID()).
				Str("_id", updated.ID()).
				Msg("Rule replaced")
		}
	}

	for idx, existing := range r.knownRules {
		for _, updated := range rules {
			if updated.SameAs(existing) && !slices.Contains(failed, updated) {
				r.knownRules[idx] = updated

				break
			}
		}
	}
}
