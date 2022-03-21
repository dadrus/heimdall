package rule

import (
	"context"
	"errors"
	"sync"
)

var (
	NoSuchElement = errors.New("no rule found")
)

type Predicate func(*Rule) (bool, error)

type Repository interface {
	FindById(context.Context, string) (*Rule, error)
	FindByPredicate(context.Context, Predicate) ([]*Rule, error)
	Count(context.Context) (int, error)
	GetAll(context.Context) ([]*Rule, error)
}

func NewRuleRepository() (Repository, error) {
	return &repository{}, nil
}

type repository struct {
	sync.RWMutex
	rules []*Rule
}

func (r *repository) FindById(_ context.Context, id string) (*Rule, error) {
	r.RLock()
	defer r.RUnlock()

	for i := range r.rules {
		rule := r.rules[i]
		if rule.ID == id {
			return rule, nil
		}
	}

	return nil, NoSuchElement
}

func (r *repository) FindByPredicate(_ context.Context, pred Predicate) ([]*Rule, error) {
	var matched []*Rule

	r.RLock()
	defer r.RUnlock()

	for _, rule := range r.rules {
		if b, err := pred(rule); err != nil {
			return nil, err
		} else if b {
			matched = append(matched, rule)
		}
	}

	if len(matched) == 0 {
		return nil, NoSuchElement
	}

	return matched, nil
}

func (r *repository) Count(_ context.Context) (int, error) {
	r.RLock()
	defer r.RUnlock()

	return len(r.rules), nil
}

func (r *repository) GetAll(_ context.Context) ([]*Rule, error) {
	return nil, nil
}
