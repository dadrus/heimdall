package rules

import (
	"errors"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrUnsupportedRuleSetVersion = errors.New("unsupported rule set version")

type ruleSetProcessor struct {
	q event.RuleSetChangedEventQueue
	f rule.Factory
	l zerolog.Logger
}

func newRuleSetProcessor(
	queue event.RuleSetChangedEventQueue, factory rule.Factory, logger zerolog.Logger,
) rule.SetProcessor {
	return &ruleSetProcessor{
		q: queue,
		f: factory,
		l: logger,
	}
}

func (p *ruleSetProcessor) isVersionSupported(_ string) bool {
	return true
}

func (p *ruleSetProcessor) loadRules(ruleSet *config.RuleSet) ([]rule.Rule, error) {
	rules := make([]rule.Rule, len(ruleSet.Rules))

	for idx, rc := range ruleSet.Rules {
		rul, err := p.f.CreateRule(ruleSet.Source, rc)
		if err != nil {
			return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed loading rule").CausedBy(err)
		}

		rules[idx] = rul
	}

	return rules, nil
}

func (p *ruleSetProcessor) OnCreated(ruleSet *config.RuleSet) error {
	if !p.isVersionSupported(ruleSet.Version) {
		return ErrUnsupportedRuleSetVersion
	}

	rules, err := p.loadRules(ruleSet)
	if err != nil {
		return err
	}

	evt := event.RuleSetChanged{
		Source:     ruleSet.Source,
		Name:       ruleSet.Name,
		Rules:      rules,
		ChangeType: event.Create,
	}

	p.sendEvent(evt)

	return nil
}

func (p *ruleSetProcessor) OnUpdated(ruleSet *config.RuleSet) error {
	if !p.isVersionSupported(ruleSet.Version) {
		return ErrUnsupportedRuleSetVersion
	}

	rules, err := p.loadRules(ruleSet)
	if err != nil {
		return err
	}

	evt := event.RuleSetChanged{
		Source:     ruleSet.Source,
		Name:       ruleSet.Name,
		Rules:      rules,
		ChangeType: event.Update,
	}

	p.sendEvent(evt)

	return nil
}

func (p *ruleSetProcessor) OnDeleted(ruleSet *config.RuleSet) error {
	if !p.isVersionSupported(ruleSet.Version) {
		return ErrUnsupportedRuleSetVersion
	}

	evt := event.RuleSetChanged{
		Source:     ruleSet.Source,
		Name:       ruleSet.Name,
		ChangeType: event.Remove,
	}

	p.sendEvent(evt)

	return nil
}

func (p *ruleSetProcessor) sendEvent(evt event.RuleSetChanged) {
	p.l.Info().
		Str("_src", evt.Source).
		Str("_type", evt.ChangeType.String()).
		Msg("Rule set changed")
	p.q <- evt
}
