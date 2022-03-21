package rule

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"golang.org/x/exp/slices"
)

var (
	ErrMatchesNoRule          = errors.New("requested url does not match any rules")
	ErrMatchesMoreThanOneRule = errors.New("expected exactly one rule but found multiple rules")
)

type RuleMatcher interface {
	Match(ctx context.Context, method string, u *url.URL) (*Rule, error)
}

func NewRuleMatcher(r Repository, me MatchingEngine) RuleMatcher {
	return &ruleMatcher{
		r:  r,
		me: me,
	}
}

type ruleMatcher struct {
	r  Repository
	me MatchingEngine
}

func (m *ruleMatcher) Match(ctx context.Context, method string, u *url.URL) (*Rule, error) {
	if u == nil {
		return nil, errors.New("nil URL provided")
	}

	rules, err := m.r.FindByPredicate(ctx, func(rule *Rule) (bool, error) {
		return m.me.IsMatching(rule.Match.URL, fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path))
	})
	if err != nil {
		return nil, err
	}
	if len(rules) > 1 {
		return nil, ErrMatchesMoreThanOneRule
	}

	if slices.Contains(rules[0].Match.Methods, method) {
		return rules[0], nil
	} else {
		return nil, ErrMatchesNoRule
	}
}
