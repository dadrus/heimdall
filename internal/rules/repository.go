package rules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/rules/provider"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/exp/slices"
)

type Repository interface {
	FindRule(requestUrl *url.URL) (Rule, error)
}

func NewRepository(queue provider.RuleSetChangedEventQueue, c config.Configuration, hf pipeline.HandlerFactory) (Repository, error) {
	return &repository{
		hf:    hf,
		dpc:   c.Rules.Default,
		queue: queue,
		quit:  make(chan bool),
	}, nil
}

type repository struct {
	hf    pipeline.HandlerFactory
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
		rule, err := r.newRule(srcId, rc)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}

	return rules, nil
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

func (r *repository) newRule(srcId string, rc config.RuleConfig) (*rule, error) {
	an, err := r.hf.CreateAuthenticator(rc.Authenticators)
	if err != nil {
		return nil, err
	}

	az, err := r.hf.CreateAuthorizer(rc.Authorizer)
	if err != nil {
		return nil, err
	}

	h, err := r.hf.CreateHydrator(rc.Hydrators)
	if err != nil {
		return nil, err
	}

	m, err := r.hf.CreateMutator(rc.Mutators)
	if err != nil {
		return nil, err
	}

	eh, err := r.hf.CreateErrorHandler(rc.ErrorHandlers)
	if err != nil {
		return nil, err
	}

	return &rule{
		id:      rc.Id,
		url:     rc.Url,
		methods: rc.Methods,
		srcId:   srcId,
		an:      an,
		az:      az,
		h:       h,
		m:       m,
		eh:      eh,
	}, nil
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

type rule struct {
	id      string
	url     string
	methods []string
	srcId   string
	an      handler.Authenticator
	az      handler.Authorizer
	h       handler.Hydrator
	m       handler.Mutator
	eh      handler.ErrorHandler
}

func (r *rule) Execute(ctx context.Context, rc handler.RequestContext) (*heimdall.SubjectContext, error) {
	sc := &heimdall.SubjectContext{}

	if err := r.an.Authenticate(ctx, rc, sc); err != nil {
		return nil, r.eh.HandleError(ctx, err)
	}

	if err := r.az.Authorize(ctx, rc, sc); err != nil {
		return nil, r.eh.HandleError(ctx, err)
	}

	if err := r.h.Hydrate(ctx, sc); err != nil {
		return nil, r.eh.HandleError(ctx, err)
	}

	if err := r.m.Mutate(ctx, sc); err != nil {
		return nil, r.eh.HandleError(ctx, err)
	}

	return sc, nil
}

func (r *rule) MatchesUrl(requestUrl *url.URL) bool {
	return true
}

func (r *rule) MatchesMethod(method string) bool {
	return slices.Contains(r.methods, method)
}

func (r *rule) Id() string {
	return r.id
}
