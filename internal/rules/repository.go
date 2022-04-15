package rules

import (
	"encoding/json"
	"errors"
	"net/url"
	"sync"

	"github.com/rs/zerolog"
	"gopkg.in/yaml.v2"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/provider"
)

var ErrNoRuleFound = errors.New("no rule found")

const defaultRuleListSize = 0

type Repository interface {
	FindRule(*url.URL) (Rule, error)
}

func NewRepository(
	queue provider.RuleSetChangedEventQueue,
	rf RuleFactory,
	logger zerolog.Logger,
) (Repository, error) {
	return &repository{
		rf:     rf,
		logger: logger,
		rules:  make([]Rule, defaultRuleListSize),
		queue:  queue,
		quit:   make(chan bool),
	}, nil
}

type repository struct {
	rf     RuleFactory
	logger zerolog.Logger

	rules []Rule
	mutex sync.RWMutex

	queue provider.RuleSetChangedEventQueue
	quit  chan bool
}

func (r *repository) FindRule(requestURL *url.URL) (Rule, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, rule := range r.rules {
		if rule.MatchesURL(requestURL) {
			return rule, nil
		}
	}

	return nil, ErrNoRuleFound
}

func (r *repository) Start() error {
	r.logger.Info().Msg("Starting rule definition loader")

	go r.watchRuleSetChanges()

	return nil
}

func (r *repository) Stop() error {
	r.logger.Info().Msg("Tearing down rule definition loader")

	r.quit <- true

	close(r.queue)

	return nil
}

func (r *repository) watchRuleSetChanges() {
	for {
		select {
		case evt, ok := <-r.queue:
			if !ok {
				r.logger.Debug().Msg("Rule set definition queue closed")
			}

			if evt.ChangeType == provider.Create {
				r.onRuleSetCreated(evt.Src, evt.Definition)
			} else if evt.ChangeType == provider.Remove {
				r.onRuleSetDeleted(evt.Src)
			}
		case <-r.quit:
			r.logger.Info().Msg("Rule definition loader stopped")

			return
		}
	}
}

func (r *repository) loadRules(srcID string, definition []byte) ([]Rule, error) {
	rcs, err := parseRuleSetFromYaml(definition)
	if err != nil {
		return nil, err
	}

	rules := make([]Rule, len(rcs))

	for idx, rc := range rcs {
		rule, err := r.rf.CreateRule(srcID, rc)
		if err != nil {
			return nil, err
		}

		rules[idx] = rule
	}

	return rules, nil
}

func (r *repository) addRule(rule Rule) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.rules = append(r.rules, rule)

	r.logger.Debug().Str("src", rule.SrcID()).Str("id", rule.ID()).Msg("Rule added")
}

func (r *repository) removeRules(srcID string) {
	r.logger.Info().Str("src", srcID).Msg("Removing rules")

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// find all indexes for affected rules
	var idxs []int

	for idx, rule := range r.rules {
		if rule.SrcID() == srcID {
			idxs = append(idxs, idx)

			r.logger.Debug().Str("id", rule.ID()).Msg("Removing rule")
		}
	}

	// if all rules should be dropped, just create a new slice
	if len(idxs) == len(r.rules) {
		r.rules = make([]Rule, defaultRuleListSize)

		return
	}

	// move the elements from the end of the rules slice to the found positions
	// end set the corresponding "emptied" values to nil
	for i, idx := range idxs {
		tailIdx := len(r.rules) - (1 + i)

		r.rules[idx] = r.rules[tailIdx]

		// the below reslice preserves the capacity of the slice
		// so this is required to avoid memory leaks
		r.rules[tailIdx] = nil
	}

	// reslice
	r.rules = r.rules[:len(r.rules)-len(idxs)]
}

func (r *repository) onRuleSetCreated(srcID string, definition json.RawMessage) {
	// create rules
	r.logger.Info().Str("src", srcID).Msg("Loading rule set")

	rules, err := r.loadRules(srcID, definition)
	if err != nil {
		r.logger.Error().Err(err).Str("src", srcID).Msg("Failed loading rule set")
	}

	// add them
	for _, rule := range rules {
		r.addRule(rule)
	}
}

func (r *repository) onRuleSetDeleted(src string) {
	r.removeRules(src)
}

func parseRuleSetFromYaml(data []byte) ([]config.RuleConfig, error) {
	var rcs []config.RuleConfig

	if err := yaml.UnmarshalStrict(data, &rcs); err != nil {
		return nil, err
	}

	return rcs, nil
}
