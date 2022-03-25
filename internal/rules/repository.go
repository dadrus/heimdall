package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"github.com/dadrus/heimdall/internal/rules/provider"
)

type Repository interface {
	FindRule(method string, requestUrl *url.URL) (Rule, error)
}

func NewRepository(queue provider.RuleSetChangedEventQueue) (Repository, error) {
	return &repository{
		queue: queue,
		quit:  make(chan bool),
	}, nil
}

type repository struct {
	rules []*rule
	mutex sync.RWMutex

	queue provider.RuleSetChangedEventQueue
	quit  chan bool
}

func (r *repository) FindRule(method string, requestUrl *url.URL) (Rule, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	for _, rule := range r.rules {
		if rule.Matches(requestUrl, method) {
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
				if evt.ChangeType == provider.Write {
					// update rules
				} else if evt.ChangeType == provider.Create {
					// create rules
					rules, err := r.loadRules(evt.Src, evt.Definition)
					if err != nil {
						fmt.Println("error loading rule")
					}
					for _, rule := range rules {
						r.addRule(rule)
					}
				} else if evt.ChangeType == provider.Remove {
					// remove rules
					r.removeRules(evt.Src)
				}
				// Receive a work request.

			case <-r.quit:
				// We have been asked to stop.
				return
			}
		}
	}()
}

func (r *repository) Stop() {
	go func() {
		r.quit <- true
	}()
}

func (r *repository) loadRules(srcId string, definition json.RawMessage) ([]*rule, error) {
	return nil, nil
}

func (r *repository) addRule(rule *rule) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.rules = append(r.rules, rule)
}

func (r *repository) removeRules(srcId string) {
	// TODO: implement remove rule
}
