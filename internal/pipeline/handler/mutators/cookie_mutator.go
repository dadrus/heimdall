package mutators

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type cookieMutator struct{}

func NewCookieMutator(rawConfig map[string]any) (cookieMutator, error) {
	return cookieMutator{}, nil
}

func (cookieMutator) Mutate(context.Context, *heimdall.SubjectContext) error {
	return nil
}

func (cookieMutator) WithConfig(config map[string]any) (handler.Mutator, error) {
	return nil, nil
}
