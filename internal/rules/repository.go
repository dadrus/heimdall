package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/provider"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/mitchellh/mapstructure"
)

type Repository interface {
	FindRule(requestUrl *url.URL) (Rule, error)
}

func NewRepository(queue provider.RuleSetChangedEventQueue, c config.Configuration, pr pipeline.Repository) (Repository, error) {
	return &repository{
		pr:    pr,
		dpc:   c.Rules.Default,
		queue: queue,
		quit:  make(chan bool),
	}, nil
}

type repository struct {
	pr    pipeline.Repository
	dpc   config.Pipeline
	rules []*rule
	mutex sync.RWMutex

	queue provider.RuleSetChangedEventQueue
	quit  chan bool
}

func (r *repository) FindRule(requestUrl *url.URL) (Rule, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	for _, rule := range r.rules {
		if rule.MatchesUrl(requestUrl) {
			return rule, nil
		}
	}
	return nil, errors.New("no rule found")
}

func (r *repository) Start() {
	go func() {
		for {
			select {
			case evt := <-r.queue:
				if evt.ChangeType == provider.Create {
					r.onRuleSetCreated(evt.Src, evt.Definition)
				} else if evt.ChangeType == provider.Remove {
					r.onRuleSetDeleted(evt.Src)
				}
			case <-r.quit:
				// We have been asked to stop.
				return
			}
		}
	}()
}

func (r *repository) Stop() {
	r.quit <- true
}

func (r *repository) loadRules(srcId string, definition json.RawMessage) ([]*rule, error) {
	rcs, err := parseRuleSetFromYaml(definition)
	if err != nil {
		return nil, err
	}

	var rules []*rule
	for _, rc := range rcs {
		rule, err := newRule(r.pr, r.dpc, srcId, rc)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

func parseRuleSetFromYaml(data []byte) ([]config.RuleConfig, error) {
	var k = koanf.New(".")
	err := k.Load(rawbytes.Provider(data), yaml.Parser())
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var rcs []config.RuleConfig

	if err = k.UnmarshalWithConf("", rcs, koanf.UnmarshalConf{
		Tag: "koanf",
		DecoderConfig: &mapstructure.DecoderConfig{
			Result:           rcs,
			WeaklyTypedInput: true,
		},
	}); err != nil {
		return nil, err
	}

	return rcs, nil
}

func (r *repository) addRule(rule *rule) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.rules = append(r.rules, rule)
}

func (r *repository) removeRules(srcId string) {
	// TODO: implement remove rule
}

func (r *repository) onRuleSetCreated(src string, definition json.RawMessage) {
	// create rules
	rules, err := r.loadRules(src, definition)
	if err != nil {
		fmt.Println("error loading rule")
	}

	// add them
	for _, rule := range rules {
		r.addRule(rule)
	}
}

func (r *repository) onRuleSetDeleted(src string) {
	r.removeRules(src)
}
