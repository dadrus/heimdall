package rules

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

type ruleSetProcessor struct {
	q event.RuleSetChangedEventQueue
	l zerolog.Logger
}

func newRuleSetProcessor(queue event.RuleSetChangedEventQueue, logger zerolog.Logger) rule.SetProcessor {
	return &ruleSetProcessor{
		q: queue,
		l: logger,
	}
}

func (p *ruleSetProcessor) OnCreated(ruleSet *rule.SetConfiguration) {
	p.sendEvent(event.RuleSetChangedEvent{
		Src:        ruleSet.Source,
		ChangeType: event.Create,
		Rules:      ruleSet.Rules,
	})
}

func (p *ruleSetProcessor) OnUpdated(ruleSet *rule.SetConfiguration) {
	p.sendEvent(event.RuleSetChangedEvent{
		Src:        ruleSet.Source,
		ChangeType: event.Remove,
	})

	p.sendEvent(event.RuleSetChangedEvent{
		Src:        ruleSet.Source,
		ChangeType: event.Create,
		Rules:      ruleSet.Rules,
	})
}

func (p *ruleSetProcessor) OnDeleted(ruleSet *rule.SetConfiguration) {
	p.sendEvent(event.RuleSetChangedEvent{
		Src:        ruleSet.Source,
		ChangeType: event.Remove,
	})
}

func (p *ruleSetProcessor) sendEvent(evt event.RuleSetChangedEvent) {
	p.l.Info().
		Str("_src", evt.Src).
		Str("_type", evt.ChangeType.String()).
		Msg("Rule set changed")
	p.q <- evt
}
