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
	"net/url"
	"sync"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
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
		logger: logger,
		queue:  queue,
		quit:   make(chan bool),
	}
}

type repository struct {
	dr     rule.Rule
	logger zerolog.Logger

	rules []rule.Rule
	mutex sync.RWMutex

	queue event.RuleSetChangedEventQueue
	quit  chan bool
}

func (r *repository) FindRule(requestURL *url.URL) (rule.Rule, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, rul := range r.rules {
		if rul.MatchesURL(requestURL) {
			return rul, nil
		}
	}

	if r.dr != nil {
		return r.dr, nil
	}

	return nil, errorchain.NewWithMessagef(heimdall.ErrNoRuleFound,
		"no applicable rule found for %s", requestURL.String())
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
	// create rules
	r.logger.Info().Str("_src", srcID).Msg("Adding rule set")

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// add them
	r.addRules(rules)
}

func (r *repository) updateRuleSet(srcID string, rules []rule.Rule) {
	// create rules
	r.logger.Info().Str("_src", srcID).Msg("Updating rule set")

	// find all rules for the given src id
	applicable := func() []rule.Rule {
		r.mutex.Lock()
		defer r.mutex.Unlock()

		return slicex.Filter(r.rules, func(r rule.Rule) bool { return r.SrcID() == srcID })
	}()

	// find new rules
	newRules := slicex.Filter(rules, func(r rule.Rule) bool {
		var known bool

		for _, existing := range applicable {
			if existing.ID() == r.ID() {
				known = true

				break
			}
		}

		return !known
	})

	// find updated rules
	updatedRules := slicex.Filter(rules, func(r rule.Rule) bool {
		loaded := r.(*ruleImpl) // nolint: forcetypeassert

		var updated bool

		for _, existing := range applicable {
			known := existing.(*ruleImpl) // nolint: forcetypeassert

			if known.id == loaded.id && !bytes.Equal(known.hash, loaded.hash) {
				updated = true

				break
			}
		}

		return updated
	})

	// find deleted rules
	deletedRules := slicex.Filter(applicable, func(r rule.Rule) bool {
		var present bool

		for _, loaded := range rules {
			if loaded.ID() == r.ID() {
				present = true

				break
			}
		}

		return !present
	})

	func() {
		r.mutex.Lock()
		defer r.mutex.Unlock()

		// remove deleted rules
		r.removeRules(deletedRules)

		// replace updated rules
		r.replaceRules(updatedRules)

		// add new rules
		r.addRules(newRules)
	}()
}

func (r *repository) deleteRuleSet(srcID string) {
	r.logger.Info().Str("_src", srcID).Msg("Deleting rule set")

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// find all rules for the given src id
	applicable := slicex.Filter(r.rules, func(r rule.Rule) bool { return r.SrcID() == srcID })

	// remove them
	r.removeRules(applicable)
}

func (r *repository) addRules(rules []rule.Rule) {
	for _, rul := range rules {
		r.rules = append(r.rules, rul)

		r.logger.Debug().Str("_src", rul.SrcID()).Str("_id", rul.ID()).Msg("Rule added")
	}
}

func (r *repository) removeRules(rules []rule.Rule) {
	// find all indexes for affected rules
	var idxs []int

	for idx, rul := range r.rules {
		for _, tbd := range rules {
			if rul.SrcID() == tbd.SrcID() && rul.ID() == tbd.ID() {
				idxs = append(idxs, idx)

				r.logger.Debug().Str("_src", rul.SrcID()).Str("_id", rul.ID()).Msg("Rule removed")
			}
		}
	}

	// if all rules should be dropped, just create a new slice
	if len(idxs) == len(r.rules) {
		r.rules = nil

		return
	}

	// move the elements from the end of the rules slice to the found positions
	// and set the corresponding "emptied" values to nil
	for i, idx := range idxs {
		tailIdx := len(r.rules) - (1 + i)

		r.rules[idx] = r.rules[tailIdx]

		// the below re-slice preserves the capacity of the slice.
		// this is required to avoid memory leaks
		r.rules[tailIdx] = nil
	}

	// re-slice
	r.rules = r.rules[:len(r.rules)-len(idxs)]
}

func (r *repository) replaceRules(rules []rule.Rule) {
	for _, updated := range rules {
		for idx, existing := range r.rules {
			if updated.SrcID() == existing.SrcID() && existing.ID() == updated.ID() {
				r.rules[idx] = updated

				r.logger.Debug().
					Str("_src", existing.SrcID()).
					Str("_id", existing.ID()).
					Msg("Rule updated")

				break
			}
		}
	}
}
