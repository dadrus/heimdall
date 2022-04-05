package mutators

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
)

type cookieMutator struct{}

func NewCookieMutator(rawConfig map[string]any) (cookieMutator, error) {
	return cookieMutator{}, nil
}

func (cookieMutator) Mutate(ctx heimdall.Context, sub *subject.Subject) error {
	return nil
}

func (cookieMutator) WithConfig(config map[string]any) (handler.Mutator, error) {
	return nil, nil
}
