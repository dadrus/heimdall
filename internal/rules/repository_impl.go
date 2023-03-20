package rules

import (
	"context"
	"net/url"
	"sync"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

const defaultRuleListSize = 0

func newRepository(
	queue event.RuleSetChangedEventQueue,
	ruleFactory RuleFactory,
	logger zerolog.Logger,
) *repository {
	return &repository{
		rf:     ruleFactory,
		logger: logger,
		rules:  make([]rule.Rule, defaultRuleListSize),
		queue:  queue,
		quit:   make(chan bool),
	}
}

type repository struct {
	rf     RuleFactory
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

	if r.rf.HasDefaultRule() {
		return r.rf.DefaultRule(), nil
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

			if evt.ChangeType == event.Create {
				r.onRuleSetCreated(evt.Src, evt.RuleSet)
			} else if evt.ChangeType == event.Remove {
				r.onRuleSetDeleted(evt.Src)
			}
		case <-r.quit:
			r.logger.Info().Msg("Rule definition loader stopped")

			return
		}
	}
}

func (r *repository) loadRules(srcID string, ruleSet []rule.RuleConfiguration) ([]rule.Rule, error) {
	rules := make([]rule.Rule, len(ruleSet))

	for idx, rc := range ruleSet {
		rul, err := r.rf.CreateRule(srcID, rc)
		if err != nil {
			return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed loading rule").CausedBy(err)
		}

		rules[idx] = rul
	}

	return rules, nil
}

func (r *repository) addRule(rule rule.Rule) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.rules = append(r.rules, rule)

	r.logger.Debug().Str("_src", rule.SrcID()).Str("_id", rule.ID()).Msg("Rule added")
}

func (r *repository) removeRules(srcID string) {
	r.logger.Info().Str("_src", srcID).Msg("Removing rules")

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// find all indexes for affected rules
	var idxs []int

	for idx, rul := range r.rules {
		if rul.SrcID() == srcID {
			idxs = append(idxs, idx)

			r.logger.Debug().Str("_id", rul.ID()).Msg("Removing rule")
		}
	}

	// if all rules should be dropped, just create a new slice
	if len(idxs) == len(r.rules) {
		r.rules = make([]rule.Rule, defaultRuleListSize)

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

func (r *repository) onRuleSetCreated(srcID string, ruleSet []rule.RuleConfiguration) {
	// create rules
	r.logger.Info().Str("_src", srcID).Msg("Loading rule set")

	rules, err := r.loadRules(srcID, ruleSet)
	if err != nil {
		r.logger.Error().Err(err).Str("_src", srcID).Msg("Failed loading rule set")
	}

	// add them
	for _, rul := range rules {
		r.addRule(rul)
	}
}

func (r *repository) onRuleSetDeleted(src string) {
	r.removeRules(src)
}
